package requestsutls

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"requests-utls/internal/testserver"
	"requests-utls/profile"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const localProfile = `{
  "schema_version": 1,
  "name": "local-integration-test",
  "tls": {
    "min_version": 771,
    "max_version": 772,
    "cipher_suites": [4865, 4866, 4867, 49199, 49200],
    "extensions": [
      {"type":"server_name"},
      {"type":"supported_groups","values":[29,23]},
      {"type":"signature_algorithms","values":[1027,2052,1025,1283,2053,1281,2054,1537]},
      {"type":"alpn","protocols":["h2","http/1.1"]},
      {"type":"supported_versions","values":[772,771]},
      {"type":"key_share","values":[29]},
      {"type":"psk_key_exchange_modes","values":[1]}
    ]
  },
  "http2": {
    "settings": [
      {"id":1,"value":65536},
      {"id":2,"value":0},
      {"id":4,"value":6291456},
      {"id":6,"value":262144}
    ],
    "connection_window_update":15663105,
    "pseudo_header_order":[":method",":authority",":scheme",":path"]
  }
}`

func testProfile(t *testing.T) *profile.Profile {
	t.Helper()
	p, err := profile.Load([]byte(localProfile))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func testServer(t *testing.T, handler testserver.Handler) *testserver.Server {
	t.Helper()
	s, err := testserver.New(handler)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func testSession(t *testing.T, server *testserver.Server, configure func(*Options)) *Session {
	t.Helper()
	options := Options{Profile: testProfile(t), RootCAs: server.RootCAs, MaxConcurrentRequests: 128, MaxPendingRequests: 128}
	if configure != nil {
		configure(&options)
	}
	session, err := NewSession(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	return session
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for concurrent request progress")
		var zero T
		return zero
	}
}

func TestWireProfileAndInterleavedDuplicateHeaders(t *testing.T) {
	responseHeaders := []hpack.HeaderField{
		{Name: "set-cookie", Value: "a=1; Path=/"},
		{Name: "x-response", Value: "middle"},
		{Name: "set-cookie", Value: "b=2; Path=/"},
	}
	server := testServer(t, func(context.Context, testserver.Request) testserver.Response {
		return testserver.Response{Body: []byte("captured"), Headers: responseHeaders}
	})
	session := testSession(t, server, nil)
	fields := []HeaderField{
		{Name: "x-a", Value: "1"},
		{Name: "x-b", Value: "2"},
		{Name: "x-a", Value: "3"},
		{Name: "cookie", Value: "first=1"},
		{Name: "x-last", Value: "4"},
		{Name: "cookie", Value: "second=2"},
	}
	response, err := session.Do(testContext(t), Request{Method: "GET", URL: server.URL + "/capture?q=1", Headers: fields})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || string(response.Body) != "captured" || response.Protocol != "HTTP/2.0" {
		t.Fatalf("unexpected response: %+v", response)
	}
	var actualResponse []HeaderField
	for _, field := range response.Headers {
		if field.Name == "set-cookie" || field.Name == "x-response" {
			actualResponse = append(actualResponse, field)
		}
	}
	wantResponse := []HeaderField{{Name: "set-cookie", Value: "a=1; Path=/"}, {Name: "x-response", Value: "middle"}, {Name: "set-cookie", Value: "b=2; Path=/"}}
	if !reflect.DeepEqual(actualResponse, wantResponse) {
		t.Fatalf("response headers changed wire order: got %#v, want %#v", actualResponse, wantResponse)
	}
	captured := server.Snapshot()
	if len(captured.Requests) != 1 {
		t.Fatalf("captured %d requests", len(captured.Requests))
	}
	var names []string
	var ordinary []HeaderField
	for _, field := range captured.Requests[0].Headers {
		if strings.HasPrefix(field.Name, ":") {
			names = append(names, field.Name)
		} else {
			ordinary = append(ordinary, HeaderField{Name: field.Name, Value: field.Value})
		}
	}
	if !reflect.DeepEqual(names, []string{":method", ":authority", ":scheme", ":path"}) {
		t.Fatalf("pseudo-header order: %v", names)
	}
	if !reflect.DeepEqual(ordinary, fields) {
		t.Fatalf("request headers changed on wire: got %#v, want %#v", ordinary, fields)
	}
	wantSettings := []http2.Setting{{ID: 1, Val: 65536}, {ID: 2, Val: 0}, {ID: 4, Val: 6291456}, {ID: 6, Val: 262144}}
	if len(captured.Settings) != 1 || !reflect.DeepEqual(captured.Settings[0], wantSettings) {
		t.Fatalf("initial SETTINGS changed: got %v, want %v", captured.Settings, wantSettings)
	}
	if len(captured.Windows) == 0 || captured.Windows[0] != (testserver.WindowUpdate{Amount: 15663105}) {
		t.Fatalf("initial connection WINDOW_UPDATE changed: %v", captured.Windows)
	}
	if len(captured.ClientHellos) != 1 {
		t.Fatalf("captured %d TLS handshakes", len(captured.ClientHellos))
	}
	hello := parseHello(t, captured.ClientHellos[0])
	if want := []uint16{4865, 4866, 4867, 49199, 49200}; !reflect.DeepEqual(hello.ciphers, want) {
		t.Fatalf("TLS cipher order: got %v, want %v", hello.ciphers, want)
	}
	if want := []uint16{0, 10, 13, 16, 43, 51, 45}; !reflect.DeepEqual(hello.extensions, want) {
		t.Fatalf("TLS extension order: got %v, want %v", hello.extensions, want)
	}
	if !bytes.Equal(hello.payloads[10], []byte{0, 4, 0, 29, 0, 23}) {
		t.Fatalf("supported groups payload: %x", hello.payloads[10])
	}
	if !bytes.Equal(hello.payloads[43], []byte{4, 3, 4, 3, 3}) {
		t.Fatalf("supported versions payload: %x", hello.payloads[43])
	}
}

func TestSharedSessionConcurrentHeadersAndCookiesStayIsolated(t *testing.T) {
	const count = 64
	started := make(chan struct{}, count)
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	server := testServer(t, func(ctx context.Context, req testserver.Request) testserver.Response {
		marker := req.Header("x-marker")
		if marker != "" {
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				return testserver.Response{}
			}
		}
		var order []string
		for _, field := range req.Headers {
			if strings.HasPrefix(field.Name, "x-order-") {
				order = append(order, field.Name+"="+field.Value)
			}
		}
		return testserver.Response{
			Body:    []byte(marker + "|" + req.Header("cookie") + "|" + strings.Join(order, ",")),
			Headers: []hpack.HeaderField{{Name: "set-cookie", Value: "shared=must-not-be-replayed"}},
		}
	})
	session := testSession(t, server, nil)
	ctx := testContext(t)
	if _, err := session.Do(ctx, Request{Method: "GET", URL: server.URL + "/warmup"}); err != nil {
		t.Fatal(err)
	}
	errorsCh := make(chan error, count)
	for i := range count {
		go func() {
			marker := strconv.Itoa(i)
			first, second := "x-order-a", "x-order-b"
			if i%2 == 1 {
				first, second = second, first
			}
			headers := []HeaderField{
				{Name: "x-marker", Value: marker}, {Name: "cookie", Value: "request=" + marker},
				{Name: first, Value: marker + "-1"}, {Name: second, Value: marker + "-2"}, {Name: first, Value: marker + "-3"},
			}
			response, err := session.Do(ctx, Request{Method: "GET", URL: server.URL + "/parallel", Headers: headers})
			if err == nil {
				want := marker + "|request=" + marker + "|" + first + "=" + marker + "-1," + second + "=" + marker + "-2," + first + "=" + marker + "-3"
				if string(response.Body) != want {
					err = fmt.Errorf("request %s received %q, want %q", marker, response.Body, want)
				}
			}
			errorsCh <- err
		}()
	}
	// Every request must arrive before any response is released: this checks
	// actual multiplexing, not just eventual success of concurrent callers.
	for range count {
		await(t, started)
	}
	releaseOnce.Do(func() { close(release) })
	for range count {
		if err := await(t, errorsCh); err != nil {
			t.Error(err)
		}
	}
	captured := server.Snapshot()
	if captured.Connections != 1 || len(captured.Requests) != count+1 {
		t.Fatalf("expected %d requests multiplexed on one connection, got %d requests on %d connections", count+1, len(captured.Requests), captured.Connections)
	}
	// A response Set-Cookie never enters a shared jar in this prototype.
	response, err := session.Do(ctx, Request{Method: "GET", URL: server.URL + "/without-cookie"})
	if err != nil || string(response.Body) != "||" {
		t.Fatalf("unexpected implicit cookie state: response=%+v err=%v", response, err)
	}
}

func TestCancelStreamPreservesSiblingAndConnection(t *testing.T) {
	started := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	server := testServer(t, func(ctx context.Context, req testserver.Request) testserver.Response {
		if req.Header(":path") == "/slow" {
			started <- struct{}{}
			<-ctx.Done()
			canceled <- struct{}{}
		}
		return testserver.Response{Body: []byte("ok")}
	})
	session := testSession(t, server, nil)
	ctx := testContext(t)
	slowCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := session.Do(slowCtx, Request{Method: "GET", URL: server.URL + "/slow"})
		result <- err
	}()
	await(t, started)
	if _, err := session.Do(ctx, Request{Method: "GET", URL: server.URL + "/sibling"}); err != nil {
		t.Fatalf("sibling while slow stream active: %v", err)
	}
	cancel()
	if err := await(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled request returned %v", err)
	}
	await(t, canceled)
	if _, err := session.Do(ctx, Request{Method: "GET", URL: server.URL + "/after-cancel"}); err != nil {
		t.Fatalf("request after stream cancellation: %v", err)
	}
	captured := server.Snapshot()
	if captured.Connections != 1 || len(captured.ResetStreams) != 1 {
		t.Fatalf("cancellation must reset one stream and reuse connection: %+v", captured)
	}
}

func TestCloseCancelsActiveRequestAndIsIdempotent(t *testing.T) {
	started := make(chan struct{}, 1)
	server := testServer(t, func(ctx context.Context, req testserver.Request) testserver.Response {
		started <- struct{}{}
		<-ctx.Done()
		return testserver.Response{}
	})
	session := testSession(t, server, nil)
	result := make(chan error, 1)
	ctx := testContext(t)
	go func() {
		_, err := session.Do(ctx, Request{Method: "GET", URL: server.URL})
		result <- err
	}()
	await(t, started)
	closed := make(chan error, 1)
	go func() { closed <- session.Close() }()
	if err := await(t, closed); err != nil {
		t.Fatal(err)
	}
	if err := await(t, result); err == nil {
		t.Fatal("closing Session allowed active request to succeed")
	}
	if err := session.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := session.Do(ctx, Request{Method: "GET", URL: server.URL}); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("request after Close: %v", err)
	}
}

func TestResponseLimitAndRequestValidation(t *testing.T) {
	server := testServer(t, func(context.Context, testserver.Request) testserver.Response {
		return testserver.Response{Body: bytes.Repeat([]byte("x"), 1024)}
	})
	session := testSession(t, server, func(options *Options) { options.MaxResponseBytes = 32 })
	ctx := testContext(t)
	if _, err := session.Do(ctx, Request{Method: "GET", URL: server.URL}); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("response limit: %v", err)
	}
	before := len(server.Snapshot().Requests)
	for _, fields := range [][]HeaderField{
		{{Name: "x-test", Value: "one\r\ninjected: two"}},
		{{Name: "invalid name", Value: "x"}},
		{{Name: ":method", Value: "POST"}},
		{{Name: "connection", Value: "keep-alive"}},
	} {
		if _, err := session.Do(ctx, Request{Method: "GET", URL: server.URL, Headers: fields}); err == nil {
			t.Errorf("accepted invalid HTTP/2 fields: %#v", fields)
		}
	}
	if after := len(server.Snapshot().Requests); after != before {
		t.Fatalf("invalid requests reached server: before=%d after=%d", before, after)
	}
}

func TestHTTP1ALPNIsExplicitlyRejected(t *testing.T) {
	server, err := testserver.NewWithALPN(nil, []string{"http/1.1"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	session := testSession(t, server, nil)
	if _, err := session.Do(testContext(t), Request{Method: "GET", URL: server.URL}); err == nil || (!strings.Contains(strings.ToLower(err.Error()), "alpn") && !strings.Contains(strings.ToLower(err.Error()), "http/1.1")) {
		t.Fatalf("expected explicit unsupported ALPN error, got %v", err)
	}
}

func TestChromeProfileTransmits51764AndGeneratesFreshKeyShares(t *testing.T) {
	const path = "profiles/chrome_152.json"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var source struct {
		TLS struct {
			Extensions []struct {
				ID      uint16 `json:"id"`
				DataHex string `json:"data_hex"`
			} `json:"extensions"`
		} `json:"tls"`
	}
	if err := json.Unmarshal(data, &source); err != nil {
		t.Fatal(err)
	}
	wantPosition := -1
	var wantPayload []byte
	for i, extension := range source.TLS.Extensions {
		if extension.ID == 51764 {
			wantPosition = i
			wantPayload, err = hex.DecodeString(extension.DataHex)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if wantPosition < 0 || len(wantPayload) == 0 {
		t.Fatal("Chrome fixture must contain nonempty extension 51764")
	}
	p, err := profile.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	server := testServer(t, nil)
	for range 2 {
		session := testSession(t, server, func(options *Options) { options.Profile = p })
		if _, err := session.Do(testContext(t), Request{Method: "GET", URL: server.URL}); err != nil {
			t.Fatal(err)
		}
		if err := session.Close(); err != nil {
			t.Fatal(err)
		}
	}
	captured := server.Snapshot()
	if len(captured.ClientHellos) != 2 {
		t.Fatalf("expected two independent TLS connections, got %d", len(captured.ClientHellos))
	}
	var previousKeyShare []byte
	for i, wire := range captured.ClientHellos {
		hello := parseHello(t, wire)
		if len(hello.extensions) <= wantPosition || hello.extensions[wantPosition] != 51764 {
			t.Fatalf("connection %d: extension 51764 moved from position %d; actual IDs: %v", i, wantPosition, hello.extensions)
		}
		if !bytes.Equal(hello.payloads[51764], wantPayload) {
			t.Fatalf("connection %d: server received extension 51764 payload %x, want %x", i, hello.payloads[51764], wantPayload)
		}
		if len(hello.payloads[51]) == 0 || bytes.Equal(previousKeyShare, hello.payloads[51]) {
			t.Fatal("each connection must generate a fresh TLS key share")
		}
		previousKeyShare = hello.payloads[51]
	}
	if priority := p.HTTP2().HeaderPriority; priority != nil {
		if len(captured.HeaderPriorities) != 2 {
			t.Fatalf("profile header priority missing on wire: %v", captured.HeaderPriorities)
		}
		for _, got := range captured.HeaderPriorities {
			if got.Param.StreamDep != priority.StreamDep || got.Param.Exclusive != priority.Exclusive || int(got.Param.Weight) != int(priority.Weight)-1 {
				t.Fatalf("HEADERS priority: got %+v, profile %+v", got.Param, priority)
			}
		}
	}
}

func TestBoundedQueueCancellationReleasesCapacity(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	server := testServer(t, func(ctx context.Context, request testserver.Request) testserver.Response {
		if request.Header(":path") == "/active" {
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		return testserver.Response{Body: []byte("ok")}
	})
	session := testSession(t, server, func(options *Options) {
		options.MaxConcurrentRequests = 1
		options.MaxPendingRequests = 1
	})
	ctx := testContext(t)
	active := make(chan error, 1)
	go func() {
		_, err := session.Do(ctx, Request{Method: "GET", URL: server.URL + "/active"})
		active <- err
	}()
	await(t, started)
	queuedCtx, cancelQueued := context.WithCancel(ctx)
	defer cancelQueued()
	const attempts = 32
	results := make(chan error, attempts)
	for range attempts {
		go func() {
			_, err := session.Do(queuedCtx, Request{Method: "GET", URL: server.URL + "/queued"})
			results <- err
		}()
	}
	// Exactly one caller can remain pending while the active stream is held.
	for range attempts - 1 {
		if err := await(t, results); !errors.Is(err, ErrQueueFull) {
			t.Fatalf("full bounded queue returned %v", err)
		}
	}
	cancelQueued()
	if err := await(t, results); !errors.Is(err, context.Canceled) {
		t.Fatalf("queued cancellation returned %v", err)
	}
	if requests := server.Snapshot().Requests; len(requests) != 1 {
		t.Fatalf("queued request reached wire before admission: %v", requests)
	}
	releaseOnce.Do(func() { close(release) })
	if err := await(t, active); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Do(ctx, Request{Method: "GET", URL: server.URL + "/after"}); err != nil {
		t.Fatalf("queue cancellation leaked capacity: %v", err)
	}
}

func TestSessionSnapshotsCertificatePool(t *testing.T) {
	server := testServer(t, nil)
	roots := x509.NewCertPool()
	session := testSession(t, server, func(options *Options) { options.RootCAs = roots })
	// Caller mutation after construction must not alter this Session's trust.
	roots.AddCert(server.Certificate)
	_, err := session.Do(testContext(t), Request{Method: "GET", URL: server.URL})
	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(err, &unknownAuthority) {
		t.Fatalf("Session unexpectedly observed later RootCAs mutation: %v", err)
	}
	fresh := testSession(t, server, func(options *Options) { options.RootCAs = roots })
	if _, err := fresh.Do(testContext(t), Request{Method: "GET", URL: server.URL}); err != nil {
		t.Fatalf("new Session did not use updated roots: %v", err)
	}
}

type helloFields struct {
	ciphers    []uint16
	extensions []uint16
	payloads   map[uint16][]byte
}

func parseHello(t *testing.T, wire []byte) helloFields {
	t.Helper()
	var handshake []byte
	for len(wire) >= 5 {
		n := int(binary.BigEndian.Uint16(wire[3:5]))
		if len(wire) < 5+n {
			t.Fatal("truncated TLS record")
		}
		if wire[0] == 22 {
			handshake = append(handshake, wire[5:5+n]...)
		}
		wire = wire[5+n:]
		if len(handshake) >= 4 {
			n := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if len(handshake) >= n+4 {
				handshake = handshake[4 : n+4]
				break
			}
		}
	}
	if len(handshake) < 35 {
		t.Fatal("missing TLS ClientHello")
	}
	// Ignore dynamic random and session ID; compare serialized profile fields.
	data := handshake[34:]
	take := func(n int) []byte {
		if n < 0 || len(data) < n {
			t.Fatal("malformed ClientHello vector")
		}
		out := data[:n]
		data = data[n:]
		return out
	}
	take(int(take(1)[0]))
	cipherBytes := take(int(binary.BigEndian.Uint16(take(2))))
	out := helloFields{payloads: make(map[uint16][]byte)}
	for len(cipherBytes) >= 2 {
		out.ciphers = append(out.ciphers, binary.BigEndian.Uint16(cipherBytes[:2]))
		cipherBytes = cipherBytes[2:]
	}
	take(int(take(1)[0]))
	extensionBytes := take(int(binary.BigEndian.Uint16(take(2))))
	for len(extensionBytes) >= 4 {
		id, n := binary.BigEndian.Uint16(extensionBytes[:2]), int(binary.BigEndian.Uint16(extensionBytes[2:4]))
		extensionBytes = extensionBytes[4:]
		if len(extensionBytes) < n {
			t.Fatal("truncated extension")
		}
		out.extensions = append(out.extensions, id)
		out.payloads[id] = append([]byte(nil), extensionBytes[:n]...)
		extensionBytes = extensionBytes[n:]
	}
	return out
}
