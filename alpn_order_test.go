package requestsutls

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/chuu3/requests-utls/internal/testserver"
	"github.com/chuu3/requests-utls/profile"
)

func h1MetadataProfile(t *testing.T) *profile.Profile {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal([]byte(localProfile), &document); err != nil {
		t.Fatal(err)
	}
	// Capture metadata must not override the original ALPN's h2 offer.
	document["http_version"] = "http/1.1"
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	p, err := profile.Load(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestALPNGeneratedHostOrderWaitsForNegotiatedProtocol(t *testing.T) {
	peer := testServer(t, func(context.Context, testserver.Request) testserver.Response {
		return testserver.Response{Body: []byte("h2")}
	})
	session := testSession(t, peer, func(options *Options) { options.Profile = h1MetadataProfile(t) })
	fields := []HeaderField{{"Cookie", "a=1"}, {"X-Middle", "middle"}, {"cOOkie", "b=2"}}
	order := []string{"host", "cookie", "HOST", "x-middle", "cookie"}
	originalOrder := append([]string(nil), order...)
	for range 2 {
		response, err := session.Do(testContext(t), Request{URL: peer.URL, Headers: fields, HeadersOrder: order})
		if err != nil || response.Protocol != "HTTP/2.0" || string(response.Body) != "h2" {
			t.Fatalf("H1-only generated Host rejected an actual H2 request: response=%+v err=%v", response, err)
		}
	}
	snapshot := peer.Snapshot()
	if snapshot.Connections != 1 || len(snapshot.ClientHellos) != 1 || len(snapshot.Requests) != 2 {
		t.Fatalf("ALPN discovery must hand off its original connection: connections=%d hellos=%d requests=%d", snapshot.Connections, len(snapshot.ClientHellos), len(snapshot.Requests))
	}
	for _, request := range snapshot.Requests {
		var regular []HeaderField
		for _, field := range request.Headers {
			if !strings.HasPrefix(field.Name, ":") {
				regular = append(regular, HeaderField{field.Name, field.Value})
			}
		}
		want := []HeaderField{{"cookie", "a=1"}, {"x-middle", "middle"}, {"cookie", "b=2"}}
		if !reflect.DeepEqual(regular, want) {
			t.Fatalf("H2 absent Host ordering/cookie interleaving: got=%+v want=%+v", regular, want)
		}
	}
	if !reflect.DeepEqual(order, originalOrder) {
		t.Fatal("protocol discovery mutated the caller's order")
	}
}

func TestALPNGeneratedHostOrderRejectsActualHTTP1BeforeRequest(t *testing.T) {
	for _, mode := range []string{"plain", "forced", "known", "discover"} {
		t.Run(mode, func(t *testing.T) {
			peer := newH1WirePeer(t, mode != "plain", []string{"http/1.1"}, func(context.Context, h1WireRequest) (string, bool) {
				return h1Reply("ok"), false
			})
			session := h1Session(t, peer, func(options *Options) {
				options.Profile = h1MetadataProfile(t)
				options.ForceHTTP1 = mode == "forced"
				if mode == "known" {
					options.Profile = testProfile(t) // H2-first handshake learns H1.
				}
			})
			wantRequests, wantConnections := 0, 0
			if mode == "known" {
				if _, err := session.Do(testContext(t), Request{URL: peer.URL}); err != nil {
					t.Fatal(err)
				}
				wantRequests, wantConnections = 1, 1
			}
			if mode == "discover" {
				wantConnections = 1 // Only the TLS handshake is needed to select H1.
			}
			for range 2 {
				response, err := session.Do(testContext(t), Request{URL: peer.URL, HeadersOrder: []string{"host", "HOST"}})
				if !errors.Is(err, ErrInvalidRequest) || response != nil {
					t.Fatalf("invalid H1 generated Host order: response=%+v err=%v", response, err)
				}
			}
			peer.mu.Lock()
			connections, requests := peer.accepted, len(peer.requests)
			peer.mu.Unlock()
			if connections != wantConnections || requests != wantRequests {
				t.Fatalf("invalid H1 request reached peer or unnecessarily dialed: connections=%d want=%d requests=%d want=%d", connections, wantConnections, requests, wantRequests)
			}
			// An ALPN-only connection remains usable; invalid ordering writes no HTTP.
			if response, err := session.Do(testContext(t), Request{URL: peer.URL}); err != nil || string(response.Body) != "ok" {
				t.Fatalf("valid request after order rejection: response=%+v err=%v", response, err)
			}
			peer.mu.Lock()
			defer peer.mu.Unlock()
			if peer.accepted != 1 || len(peer.requests) != wantRequests+1 {
				t.Fatalf("order rejection prevented connection reuse: connections=%d requests=%d", peer.accepted, len(peer.requests))
			}
		})
	}
}
