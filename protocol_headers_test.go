package requestsutls

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/chuu3/requests-utls/internal/testserver"
)

func protocolHeaderSession(t *testing.T, metadataH1 bool) (*Session, *testserver.Server) {
	t.Helper()
	peer := testServer(t, func(context.Context, testserver.Request) testserver.Response {
		return testserver.Response{Body: []byte("ok")}
	})
	session := testSession(t, peer, func(options *Options) {
		if metadataH1 {
			options.Profile = h1MetadataProfile(t)
		}
	})
	return session, peer
}

func protocolRegularFields(request testserver.Request) []HeaderField {
	var fields []HeaderField
	for _, field := range request.Headers {
		if !strings.HasPrefix(field.Name, ":") {
			fields = append(fields, HeaderField{field.Name, field.Value})
		}
	}
	return fields
}

func TestHTTP2ProtocolFilteringKeepsAuthorityOrderAndConnectionReuse(t *testing.T) {
	for _, metadataH1 := range []bool{false, true} {
		name := "h2_metadata"
		if metadataH1 {
			name = "h1_metadata_alpn_h2"
		}
		t.Run(name, func(t *testing.T) {
			session, peer := protocolHeaderSession(t, metadataH1)
			fields := []HeaderField{
				{"X-Dupe", "one"}, {"hOsT", "localhost:1"},
				{"Connection", "close, X-Hop, Trailer"}, {"Cookie", "first=1"},
				{"X-Hop", "remove-one"}, {"Keep-Alive", "timeout=5"},
				{"Proxy-Connection", "keep-alive"}, {"Transfer-Encoding", "chunked"},
				{"Upgrade", "h2c"}, {"HTTP2-Settings", "unused"},
				{"connection", "x-Other"}, {"x-hop", "remove-two"},
				{"TE", "TrAiLeRs"}, {"te", "gzip, trailers"},
				{"cookie", "second=2"}, {"x-dupe", "two"},
				{"Authorization", "fixture-token"}, {"X-Other", "remove"},
				{"Trailer", "X-Trailer"},
			}
			// Physical Host and removed hop fields are absent during H2 order
			// validation, so even repeated template entries are ignored.
			order := []string{"host", "HOST", "x-other", "X-OTHER", "connection", "connection", "cookie", "x-dupe", "te", "content-length", "cookie", "x-dupe", "authorization"}
			originalFields := append([]HeaderField(nil), fields...)
			originalOrder := append([]string(nil), order...)
			body := []byte("界")
			for range 2 {
				response, err := session.Do(testContext(t), Request{Method: "POST", URL: peer.URL + "/filtered?q=1", Headers: fields, HeadersOrder: order, Body: body})
				if err != nil || response.Protocol != "HTTP/2.0" || string(response.Body) != "ok" {
					t.Fatalf("actual H2 request failed: response=%+v err=%v", response, err)
				}
			}
			snapshot := peer.Snapshot()
			if snapshot.Connections != 1 || len(snapshot.ClientHellos) != 1 || len(snapshot.Requests) != 2 {
				t.Fatalf("filtered Connection:close or ALPN handoff broke reuse: connections=%d hellos=%d requests=%d", snapshot.Connections, len(snapshot.ClientHellos), len(snapshot.Requests))
			}
			want := []HeaderField{{"cookie", "first=1"}, {"x-dupe", "one"}, {"te", "trailers"}, {"content-length", "3"}, {"cookie", "second=2"}, {"x-dupe", "two"}, {"authorization", "fixture-token"}}
			for _, request := range snapshot.Requests {
				// Successful TLS to the URL's loopback peer also demonstrates that
				// the alternate Host was not used as the dial/SNI destination.
				if request.Header(":authority") != "localhost:1" || request.Header(":path") != "/filtered?q=1" || !bytes.Equal(request.Body, body) {
					t.Fatalf("authority/path/body changed: authority=%q path=%q body=%q", request.Header(":authority"), request.Header(":path"), request.Body)
				}
				if got := protocolRegularFields(request); !reflect.DeepEqual(got, want) {
					t.Fatalf("filtered H2 wire: got=%+v want=%+v", got, want)
				}
			}
			if !reflect.DeepEqual(fields, originalFields) || !reflect.DeepEqual(order, originalOrder) || string(body) != "界" {
				t.Fatal("protocol filtering mutated caller-owned inputs")
			}
		})
	}
}

func TestHTTP2ConnectionNominationsDoNotReintroduceFramingOrCredentials(t *testing.T) {
	for _, metadataH1 := range []bool{false, true} {
		name := "h2_metadata"
		if metadataH1 {
			name = "h1_metadata_alpn_h2"
		}
		t.Run(name, func(t *testing.T) {
			session, peer := protocolHeaderSession(t, metadataH1)
			for _, suppliedLength := range []bool{false, true} {
				fields := []HeaderField{
					{"Host", "localhost:1"}, {"Connection", "Host, Content-Length, Authorization, TE, Trailer, close"},
					{"Authorization", "fixture-one"}, {"authorization", "fixture-two"},
					{"TE", "trailers"}, {"Trailer", "X-Final"},
					{"Cookie", "a=1"}, {"X-Middle", "kept"}, {"cookie", "b=2"},
				}
				if suppliedLength {
					fields = append(fields, HeaderField{"Content-Length", "999"})
				}
				order := []string{"content-length", "content-length", "host", "host", "authorization", "authorization", "te", "te", "cookie", "x-middle", "cookie"}
				originalFields := append([]HeaderField(nil), fields...)
				originalOrder := append([]string(nil), order...)
				response, err := session.Do(testContext(t), Request{Method: "POST", URL: peer.URL, Headers: fields, HeadersOrder: order, Body: []byte("雪🙂")})
				if err != nil || response.StatusCode != 200 {
					t.Fatalf("nominated fields failed, suppliedLength=%t: response=%+v err=%v", suppliedLength, response, err)
				}
				if !reflect.DeepEqual(fields, originalFields) || !reflect.DeepEqual(order, originalOrder) {
					t.Fatal("nominated fields mutated caller inputs")
				}
			}
			snapshot := peer.Snapshot()
			if snapshot.Connections != 1 || len(snapshot.Requests) != 2 {
				t.Fatalf("nominations broke connection reuse: connections=%d requests=%d", snapshot.Connections, len(snapshot.Requests))
			}
			want := []HeaderField{{"cookie", "a=1"}, {"x-middle", "kept"}, {"cookie", "b=2"}}
			for _, request := range snapshot.Requests {
				if got := protocolRegularFields(request); !reflect.DeepEqual(got, want) {
					t.Fatalf("nominated regular field survived: got=%+v want=%+v", got, want)
				}
				if request.Header(":authority") != "localhost:1" || string(request.Body) != "雪🙂" {
					t.Fatal("removing regular Host/Content-Length lost authority or request body")
				}
			}
		})
	}
}

func TestProtocolHeaderSafetyRejectsBeforeFilteringOrTLS(t *testing.T) {
	for _, metadataH1 := range []bool{false, true} {
		session, peer := protocolHeaderSession(t, metadataH1)
		for _, fields := range [][]HeaderField{
			{{"Connection", "Content-Length"}, {"Content-Length", "3\r\nX-Injected: yes"}},
			{{"Connection", "X-Hop"}, {"X-Hop", "one\r\nX-Injected: yes"}},
			{{"Connection", "Content-Length"}, {"Content-Length", "1"}, {"content-length", "1"}},
			{{"Connection", "Host"}, {"Host", "localhost:1"}, {"host", "localhost:2"}},
			{{"Connection", "Proxy-Authorization"}, {"Proxy-Authorization", "fixture-token"}},
		} {
			response, err := session.Do(testContext(t), Request{Method: "POST", URL: peer.URL, Headers: fields, Body: []byte("abc")})
			if !errors.Is(err, ErrInvalidRequest) || response != nil {
				t.Fatalf("unsafe original fields were normalized away: response=%+v err=%v", response, err)
			}
		}
		response, err := session.Do(testContext(t), Request{URL: peer.URL, Headers: []HeaderField{{"Connection", "X-Hop"}}, HeadersOrder: []string{"X-Hop\r\nInjected"}})
		if !errors.Is(err, ErrInvalidRequest) || response != nil {
			t.Fatalf("invalid removed order name accepted: response=%+v err=%v", response, err)
		}
		snapshot := peer.Snapshot()
		if snapshot.Connections != 0 || len(snapshot.Requests) != 0 {
			t.Fatalf("common validation performed network IO: connections=%d requests=%d", snapshot.Connections, len(snapshot.Requests))
		}
	}
}

func TestHTTP2RetainedTECardinalityAndUnsupportedTrailersRejectBeforeHTTPWrite(t *testing.T) {
	for _, metadataH1 := range []bool{false, true} {
		session, peer := protocolHeaderSession(t, metadataH1)
		for _, input := range []Request{
			{Headers: []HeaderField{{"TE", "trailers"}, {"te", "gzip"}}, HeadersOrder: []string{"te", "TE"}},
			{Headers: []HeaderField{{"Trailer", "X-Final"}}},
		} {
			input.URL = peer.URL
			response, err := session.Do(testContext(t), input)
			if !errors.Is(err, ErrInvalidRequest) || response != nil {
				t.Fatalf("invalid surviving H2 fields accepted: response=%+v err=%v", response, err)
			}
		}
		if got := len(peer.Snapshot().Requests); got != 0 {
			t.Fatalf("invalid H2 request reached peer: %d requests", got)
		}
		if response, err := session.Do(testContext(t), Request{URL: peer.URL}); err != nil || response.StatusCode != 200 {
			t.Fatalf("validation rejection poisoned session: response=%+v err=%v", response, err)
		}
		if snapshot := peer.Snapshot(); snapshot.Connections != 1 || len(snapshot.Requests) != 1 {
			t.Fatalf("validation rejection lost a negotiated connection: connections=%d requests=%d", snapshot.Connections, len(snapshot.Requests))
		}
	}
}

func TestHTTP1UnsupportedFieldsRemainRejectedAfterActualProtocolSelection(t *testing.T) {
	for _, protocol := range []string{"http1_plain", "http1_forced", "http1_fallback"} {
		t.Run(protocol, func(t *testing.T) {
			session, endpoint, requests := generatedHeaderPeer(t, protocol, nil)
			for _, field := range []HeaderField{{"Transfer-Encoding", "chunked"}, {"Upgrade", "h2c"}, {"Proxy-Connection", "keep-alive"}, {"Trailer", "X-Final"}} {
				response, err := session.Do(testContext(t), Request{URL: endpoint, Headers: []HeaderField{field}})
				if !errors.Is(err, ErrInvalidRequest) || response != nil {
					t.Fatalf("H1-only rejection lost for %s: response=%+v err=%v", field.Name, response, err)
				}
			}
			if got := requests.Load(); got != 0 {
				t.Fatalf("unsupported H1 request reached peer: %d requests", got)
			}
			if response, err := session.Do(testContext(t), Request{URL: endpoint}); err != nil || response.StatusCode != 200 {
				t.Fatalf("H1 rejection poisoned session: response=%+v err=%v", response, err)
			}
		})
	}
}
