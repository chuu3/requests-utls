package requestsutls

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/http2/hpack"
	"requests-utls/internal/testserver"
)

func TestRequestHeadersOrder(t *testing.T) {
	a1 := HeaderField{Name: "x-a", Value: "1"}
	b2 := HeaderField{Name: "x-b", Value: "2"}
	a3 := HeaderField{Name: "x-a", Value: "3"}
	c4 := HeaderField{Name: "x-c", Value: "4"}
	b5 := HeaderField{Name: "x-b", Value: "5"}
	input := []HeaderField{a1, b2, a3, c4, b5}
	tests := []struct {
		name  string
		order []string
		want  []HeaderField
	}{
		{"nil preserves exact order", nil, input},
		{"empty preserves exact order", []string{}, input},
		{"whole groups", []string{"x-b", "x-a"}, []HeaderField{b2, b5, a1, a3, c4}},
		{"individual occurrences", []string{"x-a", "x-b", "x-a", "x-b"}, []HeaderField{a1, b2, a3, b5, c4}},
		{"mixed groups and occurrences", []string{"x-a", "x-b", "x-a"}, []HeaderField{a1, b2, b5, a3, c4}},
		{"unlisted fields keep relative order", []string{"x-c"}, []HeaderField{c4, a1, b2, a3, b5}},
		{"absent template names ignored", []string{"accept", "x-b", "x-a", "accept", "x-a"}, []HeaderField{b2, b5, a1, a3, c4}},
		{"only absent names", []string{"accept", "accept"}, input},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			originalHeaders := append([]HeaderField(nil), input...)
			originalOrder := append([]string{}, test.order...)
			_, fields, err := prepareRequest(context.Background(), Request{
				URL: "https://example.test/", Headers: input, HeadersOrder: test.order,
			})
			if err != nil {
				t.Fatal(err)
			}
			got := make([]HeaderField, 0, len(fields))
			for _, field := range fields {
				got = append(got, HeaderField{Name: field.Name, Value: field.Value})
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("got %#v, want %#v", got, test.want)
			}
			if !reflect.DeepEqual(input, originalHeaders) || !reflect.DeepEqual(append([]string{}, test.order...), originalOrder) {
				t.Fatal("preparing a request changed caller headers or header order")
			}
		})
	}
}

func TestRequestHeadersOrderRejectsInvalidNamesAndAmbiguousRepeats(t *testing.T) {
	tests := []struct {
		name    string
		headers []HeaderField
		order   []string
		message string
	}{
		{"pseudo", nil, []string{":path"}, "headers_order[0]"},
		{"uppercase", nil, []string{"X-A"}, "headers_order[0]"},
		{"empty", nil, []string{""}, "headers_order[0]"},
		{"space", nil, []string{"x a"}, "headers_order[0]"},
		{"newline", nil, []string{"x-a\r\nx-b"}, "headers_order[0]"},
		{"invalid absent name", nil, []string{"accept", ":authority"}, "headers_order[1]"},
		{"too many repeats", []HeaderField{{Name: "x-a", Value: "1"}}, []string{"x-a", "x-a"}, "occurs 2 times in order but 1 times in headers"},
		{"too few repeats", []HeaderField{{Name: "x-a", Value: "1"}, {Name: "x-a", Value: "2"}, {Name: "x-a", Value: "3"}}, []string{"x-a", "x-a"}, "occurs 2 times in order but 3 times in headers"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := prepareRequest(context.Background(), Request{
				URL: "https://example.test/", Headers: test.headers, HeadersOrder: test.order,
			})
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("got error %v, want containing %q", err, test.message)
			}
		})
	}
	_, fields, err := prepareRequest(context.Background(), Request{
		URL: "https://example.test/", HeadersOrder: []string{"accept", "accept"},
	})
	if err != nil || len(fields) != 0 {
		t.Fatalf("absent repeated names must be ignored: fields=%v err=%v", fields, err)
	}
}

func TestSharedSessionConcurrentRequestHeadersOrder(t *testing.T) {
	const count = 64
	started := make(chan struct{}, count)
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	server := testServer(t, func(ctx context.Context, request testserver.Request) testserver.Response {
		if request.Header("x-marker") != "" {
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				return testserver.Response{}
			}
		}
		regular := make([]HeaderField, 0, len(request.Headers))
		for _, field := range request.Headers {
			if !strings.HasPrefix(field.Name, ":") {
				regular = append(regular, HeaderField{Name: field.Name, Value: field.Value})
			}
		}
		body, _ := json.Marshal(regular)
		return testserver.Response{Body: body, Headers: []hpack.HeaderField{{Name: "set-cookie", Value: "shared=must-not-be-replayed"}}}
	})
	session := testSession(t, server, nil)
	ctx := testContext(t)
	profileHash := session.ProfileHash()
	if _, err := session.Do(ctx, Request{URL: server.URL + "/warmup"}); err != nil {
		t.Fatal(err)
	}
	// These reusable templates are shared by concurrent callers. Header values
	// and cookies differ per request while all input field names stay identical.
	templates := [][]string{
		{"x-b", "cookie", "x-a"},
		{"x-a", "cookie", "x-b", "x-a", "cookie"},
		nil,
	}
	errorsCh := make(chan error, count)
	for i := range count {
		go func() {
			marker := HeaderField{Name: "x-marker", Value: strconv.Itoa(i)}
			cookie1 := HeaderField{Name: "cookie", Value: "first=" + marker.Value}
			cookie2 := HeaderField{Name: "cookie", Value: "second=" + marker.Value}
			a1 := HeaderField{Name: "x-a", Value: marker.Value + "-1"}
			b2 := HeaderField{Name: "x-b", Value: marker.Value + "-2"}
			a3 := HeaderField{Name: "x-a", Value: marker.Value + "-3"}
			last := HeaderField{Name: "x-last", Value: marker.Value + "-4"}
			headers := []HeaderField{marker, cookie1, a1, b2, a3, last, cookie2}
			var want []HeaderField
			switch i % len(templates) {
			case 0:
				want = []HeaderField{b2, cookie1, cookie2, a1, a3, marker, last}
			case 1:
				want = []HeaderField{a1, cookie1, b2, a3, cookie2, marker, last}
			case 2:
				want = headers
			}
			response, err := session.Do(ctx, Request{
				URL: server.URL + "/parallel", Headers: headers, HeadersOrder: templates[i%len(templates)],
			})
			if err == nil {
				var got []HeaderField
				err = json.Unmarshal(response.Body, &got)
				if err == nil && !reflect.DeepEqual(got, want) {
					err = fmt.Errorf("request %d wire headers: got %#v, want %#v", i, got, want)
				}
			}
			errorsCh <- err
		}()
	}
	// All streams reach the peer before any response, proving multiplexing on
	// one shared Session rather than merely serial eventual success.
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
		t.Fatalf("expected %d requests on one connection; got %d requests on %d connections", count+1, len(captured.Requests), captured.Connections)
	}
	if session.ProfileHash() != profileHash {
		t.Fatal("request headers_order changed Session profile")
	}
	response, err := session.Do(ctx, Request{URL: server.URL + "/no-implicit-cookie"})
	if err != nil || string(response.Body) != "[]" {
		t.Fatalf("request inherited shared header/cookie state: response=%+v err=%v", response, err)
	}
}
