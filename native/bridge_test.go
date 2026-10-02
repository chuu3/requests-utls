package native

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	requestsutls "github.com/chuu3/requests-utls"
	"github.com/chuu3/requests-utls/internal/testserver"

	"golang.org/x/net/http2/hpack"
)

const testProfile = `{
 "schema_version":1,"name":"native-test",
 "tls":{"min_version":771,"max_version":772,"cipher_suites":[4865,4866,4867,49199,49200],
 "extensions":[{"type":"server_name"},{"type":"supported_groups","values":[29,23]},
 {"type":"signature_algorithms","values":[1027,2052,1025,1283,2053,1281,2054,1537]},
 {"type":"alpn","protocols":["h2"]},{"type":"supported_versions","values":[772,771]},
 {"type":"key_share","values":[29]},{"type":"psk_key_exchange_modes","values":[1]}]},
 "http2":{"settings":[{"id":1,"value":65536},{"id":2,"value":0},{"id":4,"value":6291456}],
 "connection_window_update":15663105,"pseudo_header_order":[":method",":authority",":scheme",":path"]}}
`

func startServer(t *testing.T, handler testserver.Handler) *testserver.Server {
	t.Helper()
	s, err := testserver.New(handler)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func newSession(t *testing.T, r *Registry, server *testserver.Server, settings map[string]any) uint64 {
	t.Helper()
	config := map[string]any{"profile": json.RawMessage(testProfile)}
	if server != nil {
		config["ca_pem"] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate.Raw}))
	}
	for k, v := range settings {
		config[k] = v
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	result := r.SessionCreate(data)
	if result.Code != OK {
		t.Fatalf("create: %d %s", result.Code, result.Data)
	}
	t.Cleanup(func() { r.SessionClose(result.Handle) })
	return result.Handle
}

func metadata(t *testing.T, url string, settings map[string]any) []byte {
	t.Helper()
	in := map[string]any{"url": url, "timeout_ms": 5000}
	for k, v := range settings {
		in[k] = v
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func poll(t *testing.T, r *Registry, sid uint64) Result {
	t.Helper()
	result := r.SessionPoll(sid, 5000)
	if result.Code == PollTimeout {
		t.Fatal("timed out waiting for native completion")
	}
	return result
}

func assertEmpty(t *testing.T, r *Registry) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.requests) != 0 {
		t.Errorf("leaked %d request handles", len(r.requests))
	}
	for _, s := range r.sessions {
		if len(s.requests) != 0 || len(s.queue) != 0 {
			t.Errorf("session retained %d requests and %d completions", len(s.requests), len(s.queue))
		}
	}
}

func TestConcurrentRequestOrderBodySnapshotsAndCookieIsolation(t *testing.T) {
	type echo struct {
		Headers []requestsutls.HeaderField `json:"headers"`
		Body    string                     `json:"body"`
	}
	server := startServer(t, func(_ context.Context, req testserver.Request) testserver.Response {
		response := echo{Body: string(req.Body)}
		for _, f := range req.Headers {
			if !strings.HasPrefix(f.Name, ":") {
				response.Headers = append(response.Headers, requestsutls.HeaderField{Name: f.Name, Value: f.Value})
			}
		}
		body, _ := json.Marshal(response)
		return testserver.Response{Headers: []hpack.HeaderField{{Name: "set-cookie", Value: "a=1"}, {Name: "set-cookie", Value: "b=2"}}, Body: body}
	})
	r := NewRegistry()
	sid := newSession(t, r, server, map[string]any{"max_concurrent_requests": 64})
	type submitted struct {
		result   Result
		expected echo
	}
	results := make(chan submitted, 64)
	var workers sync.WaitGroup
	for i := range 64 {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			value := fmt.Sprint(i)
			headers := []requestsutls.HeaderField{{Name: "x-a", Value: value + "-1"}, {Name: "x-a", Value: value + "-2"}, {Name: "x-b", Value: value}, {Name: "cookie", Value: "id=" + value}}
			order := []string{"x-a", "x-b", "x-a", "cookie"}
			ordered := []requestsutls.HeaderField{headers[0], headers[2], headers[1], headers[3]}
			if i%2 != 0 {
				order = []string{"cookie", "x-b", "x-a"}
				ordered = []requestsutls.HeaderField{headers[3], headers[2], headers[0], headers[1]}
			}
			body := []byte("payload-" + value)
			ordered = append(ordered, requestsutls.HeaderField{Name: "content-length", Value: fmt.Sprint(len(body))})
			meta := metadata(t, server.URL, map[string]any{"method": "POST", "headers": headers, "headers_order": order})
			result := r.RequestSubmit(sid, meta, body)
			for j := range body {
				body[j] = '!'
			}
			for j := range meta {
				meta[j] = '!'
			}
			results <- submitted{result, echo{Headers: ordered, Body: "payload-" + value}}
		}(i)
	}
	workers.Wait()
	close(results)
	expected := map[uint64]echo{}
	for submitted := range results {
		if submitted.result.Code != OK {
			t.Fatalf("submit: %d %s", submitted.result.Code, submitted.result.Data)
		}
		expected[submitted.result.Handle] = submitted.expected
	}
	for range 64 {
		result := poll(t, r, sid)
		if result.Code != OK {
			t.Fatalf("completion: %d %s", result.Code, result.Data)
		}
		var response responseMetadata
		if err := json.Unmarshal(result.Data, &response); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 200 || response.Protocol != "HTTP/2.0" || len(response.Headers) != 2 || response.Headers[0].Name != "set-cookie" || response.Headers[1].Value != "b=2" {
			t.Fatalf("bad response metadata: %+v", response)
		}
		body := r.RequestBody(result.Handle)
		if body.Code != OK || len(body.Data) != response.BodySize {
			t.Fatalf("body: %+v", body)
		}
		var got echo
		if err := json.Unmarshal(body.Data, &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, expected[result.Handle]) {
			t.Fatalf("request %d mixed state: got %+v want %+v", result.Handle, got, expected[result.Handle])
		}
		// Returned buffers are independent snapshots, including repeated body reads.
		body.Data[0] = '!'
		if again := r.RequestBody(result.Handle); again.Data[0] != '{' {
			t.Fatal("body alias escaped")
		}
		delete(expected, result.Handle)
		r.RequestRelease(result.Handle)
	}
	if len(expected) != 0 {
		t.Fatal("missing completions")
	}
	if result := r.SessionPoll(sid, 0); result.Code != PollTimeout {
		t.Fatalf("duplicate completion: %+v", result)
	}
	assertEmpty(t, r)
}

func TestCompletedHandlesBoundAdmissionAndReleaseIsIdempotent(t *testing.T) {
	server := startServer(t, nil)
	r := NewRegistry()
	sid := newSession(t, r, server, map[string]any{"max_concurrent_requests": 1})
	meta := metadata(t, server.URL, nil)
	first := r.RequestSubmit(sid, meta, nil)
	if first.Code != OK {
		t.Fatal(first)
	}
	if result := poll(t, r, sid); result.Code != OK {
		t.Fatalf("completion: %d %s", result.Code, result.Data)
	}
	if result := r.RequestSubmit(sid, meta, nil); result.Code != QueueFull {
		t.Fatalf("completed handle failed to bound admission: %+v", result)
	}
	if r.RequestRelease(first.Handle) != OK || r.RequestRelease(first.Handle) != OK {
		t.Fatal("release must be idempotent")
	}
	if result := r.RequestBody(first.Handle); result.Code != InvalidHandle {
		t.Fatal("released body remains accessible")
	}
	second := r.RequestSubmit(sid, meta, nil)
	if second.Code != OK || second.Handle <= first.Handle {
		t.Fatal(second)
	}
	if result := poll(t, r, sid); result.Code != OK {
		t.Fatal(result)
	}
	r.RequestRelease(second.Handle)
	assertEmpty(t, r)
}

func TestCancelDeadlineAndReleaseSuppressesCompletion(t *testing.T) {
	started := make(chan struct{}, 8)
	server := startServer(t, func(ctx context.Context, _ testserver.Request) testserver.Response {
		started <- struct{}{}
		<-ctx.Done()
		return testserver.Response{}
	})
	r := NewRegistry()
	sid := newSession(t, r, server, map[string]any{"max_concurrent_requests": 2})
	first := r.RequestSubmit(sid, metadata(t, server.URL, nil), nil)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("request never arrived")
	}
	if r.RequestCancel(first.Handle) != OK {
		t.Fatal("cancel failed")
	}
	result := poll(t, r, sid)
	if result.Code != Canceled || result.Handle != first.Handle {
		t.Fatalf("cancel: %+v", result)
	}
	r.RequestRelease(first.Handle)
	second := r.RequestSubmit(sid, metadata(t, server.URL, map[string]any{"timeout_ms": 50}), nil)
	result = poll(t, r, sid)
	if result.Code != Deadline || result.Handle != second.Handle {
		t.Fatalf("deadline: %+v", result)
	}
	r.RequestRelease(second.Handle)
	third := r.RequestSubmit(sid, metadata(t, server.URL, nil), nil)
	r.RequestRelease(third.Handle)
	r.mu.Lock()
	s := r.sessions[sid]
	r.mu.Unlock()
	s.wg.Wait()
	if result := r.SessionPoll(sid, 0); result.Code != PollTimeout {
		t.Fatalf("released request emitted completion: %+v", result)
	}
	assertEmpty(t, r)
}

func TestCloseRacesPollCancelReleaseAndSubmitWithoutLeaks(t *testing.T) {
	server := startServer(t, func(ctx context.Context, _ testserver.Request) testserver.Response {
		<-ctx.Done()
		return testserver.Response{}
	})
	r := NewRegistry()
	sid := newSession(t, r, server, nil)
	meta := metadata(t, server.URL, nil)
	requests := make([]uint64, 32)
	for i := range requests {
		result := r.RequestSubmit(sid, meta, nil)
		if result.Code != OK {
			t.Fatal(result)
		}
		requests[i] = result.Handle
	}
	var workers sync.WaitGroup
	pollDone := make(chan Result, 1)
	go func() { pollDone <- r.SessionPoll(sid, -1) }()
	for i := range 32 {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			switch i % 4 {
			case 0:
				r.SessionClose(sid)
			case 1:
				r.RequestCancel(requests[i])
			case 2:
				r.RequestRelease(requests[i])
			case 3:
				r.RequestSubmit(sid, meta, nil)
			}
		}(i)
	}
	workers.Wait()
	select {
	case result := <-pollDone:
		if result.Code != SessionClosed && result.Code != InvalidHandle && result.Code != Canceled {
			t.Fatalf("unexpected racing poll: %+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("close did not wake poller")
	}
	assertEmpty(t, r)
	r.mu.Lock()
	count := len(r.sessions)
	r.mu.Unlock()
	if count != 0 {
		t.Fatalf("%d session handles leaked", count)
	}
	if r.SessionClose(sid) != OK {
		t.Fatal("second close failed")
	}
}

func TestStrictInputAndErrorCodes(t *testing.T) {
	r := NewRegistry()
	for _, input := range []string{`null`, `[]`, `{} {}`, `{"unknown":true}`, `{"profile":null}`, `{"profile":` + testProfile + `,"proxy_auth":{"user":"x"}}`} {
		if result := r.SessionCreate([]byte(input)); result.Code != InvalidInput {
			t.Errorf("session accepted %s: %+v", input, result)
		}
	}
	server := startServer(t, func(_ context.Context, _ testserver.Request) testserver.Response {
		return testserver.Response{Body: []byte("long")}
	})
	sid := newSession(t, r, server, map[string]any{"max_response_bytes": 2})
	for _, input := range []string{`null`, `{}`, `{"url":"https://example.com","unknown":1}`, `{"url":"https://example.com","timeout_ms":-1}`, `{"url":"https://example.com","timeout_ms":9223372036854775807}`} {
		if result := r.RequestSubmit(sid, []byte(input), nil); result.Code != InvalidInput {
			t.Errorf("request accepted %s: %+v", input, result)
		}
	}
	if result := r.SessionPoll(sid, -2); result.Code != InvalidInput {
		t.Fatal(result)
	}
	if result := r.SessionPoll(^uint64(0), 0); result.Code != InvalidHandle {
		t.Fatal(result)
	}
	if code := r.RequestCancel(^uint64(0)); code != InvalidHandle {
		t.Fatal(code)
	}
	submitted := r.RequestSubmit(sid, metadata(t, server.URL, nil), nil)
	if submitted.Code != OK {
		t.Fatal(submitted)
	}
	if result := poll(t, r, sid); result.Code != ResponseTooLarge {
		t.Fatalf("limit: %+v", result)
	}
	r.RequestRelease(submitted.Handle)
	submitted = r.RequestSubmit(sid, metadata(t, server.URL, map[string]any{"headers_order": []string{"bad name"}}), nil)
	if submitted.Code != OK {
		t.Fatal(submitted)
	}
	if result := poll(t, r, sid); result.Code != InvalidInput {
		t.Fatalf("header validation: %+v", result)
	}
	r.RequestRelease(submitted.Handle)
	if result := ProfileImport(bytes.Repeat([]byte("x"), MaxMetadataBytes+1), false); result.Code != InvalidInput {
		t.Fatal(result)
	}
	assertEmpty(t, r)
}

func TestPhaseTimeoutMetadata(t *testing.T) {
	server := startServer(t, func(ctx context.Context, _ testserver.Request) testserver.Response {
		<-ctx.Done()
		return testserver.Response{}
	})
	r := NewRegistry()
	sid := newSession(t, r, server, map[string]any{"response_header_timeout_ms": 60})
	submitted := r.RequestSubmit(sid, metadata(t, server.URL, nil), nil)
	if submitted.Code != OK {
		t.Fatalf("submit: %s", submitted.Data)
	}
	result := poll(t, r, sid)
	if result.Code != Deadline {
		t.Fatalf("code=%d data=%s", result.Code, result.Data)
	}
	var info struct {
		Stage   string  `json:"stage"`
		Elapsed float64 `json:"elapsed_ms"`
	}
	if err := json.Unmarshal(result.Data, &info); err != nil || info.Stage != "response_headers" || info.Elapsed <= 0 {
		t.Fatalf("metadata: %s", result.Data)
	}
	r.RequestRelease(submitted.Handle)
}
