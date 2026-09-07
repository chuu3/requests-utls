package requestsutls

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/chuu3/requests-utls/internal/testserver"
)

type generatedHeaderObservation struct {
	Headers    []HeaderField
	Body       []byte
	Connection int
}

// Both fixtures inspect actual wire fields before any map-based header parsing.
func generatedHeaderPeer(t *testing.T, protocol string, beforeReply func(context.Context)) (*Session, string, *atomic.Int32) {
	t.Helper()
	observed := new(atomic.Int32)
	echo := func(ctx context.Context, request generatedHeaderObservation) []byte {
		observed.Add(1)
		if beforeReply != nil {
			beforeReply(ctx)
		}
		body, _ := json.Marshal(request)
		return body
	}
	if protocol == "http2" || protocol == "http2_from_h1" {
		peer := testServer(t, func(ctx context.Context, request testserver.Request) testserver.Response {
			captured := generatedHeaderObservation{Body: request.Body, Connection: request.Connection}
			for _, field := range request.Headers {
				if !strings.HasPrefix(field.Name, ":") {
					captured.Headers = append(captured.Headers, HeaderField{Name: field.Name, Value: field.Value})
				}
			}
			return testserver.Response{Body: echo(ctx, captured)}
		})
		return testSession(t, peer, func(options *Options) {
			if protocol == "http2_from_h1" {
				options.Profile = h1MetadataProfile(t)
			}
		}), peer.URL, observed
	}
	peer := newH1WirePeer(t, protocol != "http1_plain", []string{"http/1.1"}, func(ctx context.Context, request h1WireRequest) (string, bool) {
		body := echo(ctx, generatedHeaderObservation{Headers: request.Headers, Body: request.Body, Connection: request.Connection})
		return h1Reply(string(body)), false
	})
	session := h1Session(t, peer, func(options *Options) { options.ForceHTTP1 = protocol == "http1_forced" })
	return session, peer.URL, observed
}

func generatedHeaderHost(t *testing.T, endpoint string) HeaderField {
	t.Helper()
	parsed, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	return HeaderField{Name: "Host", Value: parsed.Host}
}

func generatedHeadersOnWire(protocol string, fields []HeaderField) []HeaderField {
	result := append([]HeaderField(nil), fields...)
	if protocol == "http2" {
		for i := range result {
			result[i].Name = strings.ToLower(result[i].Name)
		}
	}
	return result
}

func decodeGeneratedHeaders(t *testing.T, response *Response, err error) generatedHeaderObservation {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		t.Fatalf("status = %d", response.StatusCode)
	}
	var observed generatedHeaderObservation
	if err := json.Unmarshal(response.Body, &observed); err != nil {
		t.Fatal(err)
	}
	return observed
}

func TestGeneratedContentLengthUsesFinalBodyBytes(t *testing.T) {
	cases := []struct {
		name, method string
		body         []byte
		lengthName   string
		inputLength  string
		wantLength   string // Deliberately explicit: UTF-8 byte count is not rune count.
	}{
		{"missing_ascii", "POST", []byte("abc"), "", "", "3"},
		{"missing_utf8", "POST", []byte("你好🙂"), "", "", "10"},
		{"wrong_short", "POST", []byte("你好🙂"), "Content-Length", "1", "10"},
		{"wrong_long", "POST", []byte("abc"), "content-length", "99999", "3"},
		{"wrong_text", "POST", []byte("abc"), "Content-Length", "not-a-number", "3"},
		{"empty_value", "POST", []byte("abc"), "Content-Length", "", "3"},
		{"mixed_case", "POST", []byte("你好🙂"), "cOnTeNt-LeNgTh", "99999", "10"},
		{"binary", "POST", []byte{0, 255, 1}, "CONTENT-LENGTH", "0", "3"},
		{"empty_post", "POST", nil, "", "", "0"},
		{"empty_put", "PUT", nil, "", "", "0"},
		{"empty_patch", "PATCH", nil, "", "", "0"},
		{"empty_get_explicit", "GET", nil, "cOnTeNt-LeNgTh", "99", "0"},
		{"get_with_body", "GET", []byte("abc"), "", "", "3"},
		{"empty_get_without_length", "GET", nil, "", "", ""},
	}
	for _, protocol := range []string{"http1_plain", "http1_forced", "http1_fallback", "http2"} {
		t.Run(protocol, func(t *testing.T) {
			session, endpoint, _ := generatedHeaderPeer(t, protocol, nil)
			for _, test := range cases {
				t.Run(test.name, func(t *testing.T) {
					fields := []HeaderField{{Name: "X-First", Value: "before"}}
					want := append([]HeaderField(nil), fields...)
					if test.lengthName != "" {
						fields = append(fields, HeaderField{Name: test.lengthName, Value: test.inputLength})
						want = append(want, HeaderField{Name: test.lengthName, Value: test.wantLength})
					}
					fields = append(fields, HeaderField{Name: "X-Last", Value: "after"})
					want = append(want, HeaderField{Name: "X-Last", Value: "after"})
					if protocol != "http2" {
						want = append([]HeaderField{generatedHeaderHost(t, endpoint)}, want...)
					}
					if test.lengthName == "" && test.wantLength != "" {
						want = append(want, HeaderField{Name: "Content-Length", Value: test.wantLength})
					}
					original := append([]HeaderField(nil), fields...)
					response, err := session.Do(testContext(t), Request{Method: test.method, URL: endpoint, Headers: fields, Body: test.body})
					observed := decodeGeneratedHeaders(t, response, err)
					if expected := generatedHeadersOnWire(protocol, want); !reflect.DeepEqual(observed.Headers, expected) {
						t.Fatalf("wire headers = %#v, want %#v", observed.Headers, expected)
					}
					if !bytes.Equal(observed.Body, test.body) {
						t.Fatalf("wire body = %x, want %x", observed.Body, test.body)
					}
					if !reflect.DeepEqual(fields, original) {
						t.Fatalf("request normalization mutated caller-owned headers: %#v", fields)
					}
				})
			}
		})
	}
}

func TestGeneratedContentLengthParticipatesInOrder(t *testing.T) {
	for _, protocol := range []string{"http1_plain", "http1_forced", "http1_fallback", "http2"} {
		t.Run(protocol, func(t *testing.T) {
			session, endpoint, _ := generatedHeaderPeer(t, protocol, nil)
			fields := []HeaderField{{"Cookie", "a=1"}, {"X-Between", "middle"}, {"cOOkie", "b=2"}}
			order := []string{"COOKIE", "HOST", "content-length", "x-between", "cookie"}
			originalOrder := append([]string(nil), order...)
			want := []HeaderField{fields[0]}
			if protocol != "http2" {
				want[0].Value = "a=1; b=2"
				want = append(want, generatedHeaderHost(t, endpoint))
			}
			want = append(want, HeaderField{"Content-Length", "10"}, fields[1])
			if protocol == "http2" {
				want = append(want, fields[2])
			}
			for range 2 {
				response, err := session.Do(testContext(t), Request{Method: "POST", URL: endpoint, Headers: fields, HeadersOrder: order, Body: []byte("你好🙂")})
				observed := decodeGeneratedHeaders(t, response, err)
				if expected := generatedHeadersOnWire(protocol, want); !reflect.DeepEqual(observed.Headers, expected) {
					t.Fatalf("ordered wire headers = %#v, want %#v", observed.Headers, expected)
				}
			}
			if !reflect.DeepEqual(order, originalOrder) {
				t.Fatalf("shared order template was mutated: %#v", order)
			}
		})
	}
}

func TestGeneratedContentLengthRejectsRepeatedFields(t *testing.T) {
	for _, protocol := range []string{"http1_plain", "http1_forced", "http1_fallback", "http2"} {
		t.Run(protocol, func(t *testing.T) {
			session, endpoint, requests := generatedHeaderPeer(t, protocol, nil)
			for _, fields := range [][]HeaderField{
				{{"Content-Length", "3"}, {"Content-Length", "3"}},
				{{"cOnTeNt-LeNgTh", "invalid"}, {"content-length", "999"}},
			} {
				_, err := session.Do(testContext(t), Request{Method: "POST", URL: endpoint, Headers: fields, Body: []byte("abc")})
				if !errors.Is(err, ErrInvalidRequest) {
					t.Fatalf("repeated Content-Length was not rejected: %v", err)
				}
			}
			if got := requests.Load(); got != 0 {
				t.Fatalf("invalid requests reached the peer: %d", got)
			}
			response, err := session.Do(testContext(t), Request{Method: "POST", URL: endpoint, Body: []byte("abc")})
			observed := decodeGeneratedHeaders(t, response, err)
			if !bytes.Equal(observed.Body, []byte("abc")) || requests.Load() != 1 {
				t.Fatal("a rejected request prevented the next valid request")
			}
		})
	}
}

func TestGeneratedContentLengthConcurrentIsolation(t *testing.T) {
	for _, protocol := range []string{"http1_fallback", "http2"} {
		t.Run(protocol, func(t *testing.T) {
			const workers = 16
			started := make(chan struct{}, workers)
			release := make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			session, endpoint, _ := generatedHeaderPeer(t, protocol, func(ctx context.Context) {
				started <- struct{}{}
				select {
				case <-release:
				case <-ctx.Done():
				}
			})
			templates := [][]string{{"cookie", "CONTENT-LENGTH", "x-id", "cookie"}, {"x-id", "COOKIE", "content-length", "cookie"}}
			originalTemplates := [][]string{append([]string(nil), templates[0]...), append([]string(nil), templates[1]...)}
			results := make(chan error, workers)
			for i := range workers {
				go func() {
					first := HeaderField{"Cookie", fmt.Sprintf("first=%d", i)}
					middle := HeaderField{"X-ID", strconv.Itoa(i)}
					last := HeaderField{"cOOkie", fmt.Sprintf("last=%d", i)}
					length := HeaderField{"Content-Length", strconv.Itoa(3 * (i + 1))}
					fields := []HeaderField{first, middle, last}
					if i%3 == 0 {
						length.Name = "cOnTeNt-LeNgTh"
						fields = append(fields, HeaderField{length.Name, "wrong"})
					}
					original := append([]HeaderField(nil), fields...)
					wireFirst := first
					if protocol != "http2" {
						wireFirst.Value += "; " + last.Value
					}
					want := []HeaderField{wireFirst, length, middle}
					if i%2 != 0 {
						want = []HeaderField{middle, wireFirst, length}
					}
					if protocol == "http2" {
						want = append(want, last)
					} else {
						want = append([]HeaderField{generatedHeaderHost(t, endpoint)}, want...)
					}
					body := []byte(strings.Repeat("界", i+1))
					response, err := session.Do(testContext(t), Request{Method: "POST", URL: endpoint, Headers: fields, HeadersOrder: templates[i%2], Body: body})
					if err != nil {
						results <- err
						return
					}
					var observed generatedHeaderObservation
					if err = json.Unmarshal(response.Body, &observed); err == nil {
						if !reflect.DeepEqual(observed.Headers, generatedHeadersOnWire(protocol, want)) || !bytes.Equal(observed.Body, body) {
							err = fmt.Errorf("request %d received another request's fields or length: %#v", i, observed)
						} else if !reflect.DeepEqual(fields, original) {
							err = fmt.Errorf("request %d changed its caller-owned field list", i)
						}
					}
					results <- err
				}()
			}
			for range workers {
				await(t, started)
			}
			once.Do(func() { close(release) })
			for range workers {
				if err := <-results; err != nil {
					t.Error(err)
				}
			}
			if !reflect.DeepEqual(templates, originalTemplates) {
				t.Fatal("concurrent requests modified a shared order template")
			}
		})
	}
}

func TestGeneratedHeadersKeepConnectionProtocolSpecific(t *testing.T) {
	for _, protocol := range []string{"http1_plain", "http1_forced", "http1_fallback", "http2"} {
		t.Run(protocol, func(t *testing.T) {
			session, endpoint, requests := generatedHeaderPeer(t, protocol, nil)
			connection := 0
			for range 2 {
				response, err := session.Do(testContext(t), Request{Method: "POST", URL: endpoint, Body: []byte("abc")})
				observed := decodeGeneratedHeaders(t, response, err)
				for _, field := range observed.Headers {
					if strings.EqualFold(field.Name, "connection") {
						t.Fatal("Connection was automatically added")
					}
				}
				if connection != 0 && observed.Connection != connection {
					t.Fatal("implicit keep-alive did not reuse the connection")
				}
				connection = observed.Connection
			}
			fields := []HeaderField{{"X-First", "one"}, {"cOnNeCtIoN", "keep-alive"}, {"X-Last", "two"}}
			order := []string{"x-last", "CONNECTION", "host", "content-length", "x-first"}
			response, err := session.Do(testContext(t), Request{Method: "POST", URL: endpoint, Headers: fields, HeadersOrder: order, Body: []byte("abc")})
			if protocol == "http2" {
				observed := decodeGeneratedHeaders(t, response, err)
				want := generatedHeadersOnWire("http2", []HeaderField{fields[2], {"Content-Length", "3"}, fields[0]})
				if !reflect.DeepEqual(observed.Headers, want) || observed.Connection != connection || requests.Load() != 3 {
					t.Fatalf("HTTP/2 filtering changed remaining order or reuse: observed=%#v requests=%d", observed, requests.Load())
				}
				return
			}
			observed := decodeGeneratedHeaders(t, response, err)
			want := []HeaderField{fields[2], fields[1], generatedHeaderHost(t, endpoint), {"Content-Length", "3"}, fields[0]}
			if !reflect.DeepEqual(observed.Headers, want) || observed.Connection != connection {
				t.Fatalf("explicit Connection lost casing/order or reuse: %#v", observed)
			}
		})
	}
}
