package requestsutls

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chuu3/requests-utls/internal/testserver"
	"github.com/chuu3/requests-utls/profile"
)

type h1WireRequest struct {
	Line       string
	Headers    []HeaderField
	Body       []byte
	Connection int
	DidResume  bool
}

type h1WirePeer struct {
	URL      string
	Roots    *x509.CertPool
	mu       sync.Mutex
	accepted int
	hellos   [][]string
	requests []h1WireRequest
}

func newH1WirePeer(t *testing.T, secure bool, protocols []string, handler func(context.Context, h1WireRequest) (string, bool)) *h1WirePeer {
	t.Helper()
	p := &h1WirePeer{}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var config *tls.Config
	scheme := "http"
	if secure {
		certSource := httptest.NewTLSServer(http.NotFoundHandler())
		config = certSource.TLS.Clone()
		p.Roots = x509.NewCertPool()
		p.Roots.AddCert(certSource.Certificate())
		certSource.Close()
		config.NextProtos = protocols
		config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			p.mu.Lock()
			p.hellos = append(p.hellos, append([]string(nil), hello.SupportedProtos...))
			p.mu.Unlock()
			return nil, nil
		}
		scheme = "https"
	}
	p.URL = scheme + "://" + listener.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var connMu sync.Mutex
	conns := make(map[net.Conn]bool)
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			connMu.Lock()
			conns[raw] = true
			connMu.Unlock()
			p.mu.Lock()
			p.accepted++
			id := p.accepted
			p.mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { raw.Close(); connMu.Lock(); delete(conns, raw); connMu.Unlock() }()
				var conn net.Conn = raw
				resumed := false
				if secure {
					secured := tls.Server(raw, config)
					if secured.HandshakeContext(ctx) != nil {
						return
					}
					resumed = secured.ConnectionState().DidResume
					conn = secured
				}
				reader := bufio.NewReader(conn)
				for {
					var wire bytes.Buffer
					var captured h1WireRequest
					for index := 0; ; index++ {
						line, err := reader.ReadString('\n')
						if err != nil {
							return
						}
						wire.WriteString(line)
						line = strings.TrimSuffix(line, "\r\n")
						if index == 0 {
							captured.Line = line
							continue
						}
						if line == "" {
							break
						}
						name, value, _ := strings.Cut(line, ":")
						captured.Headers = append(captured.Headers, HeaderField{Name: name, Value: strings.TrimSpace(value)})
					}
					parser := bufio.NewReader(io.MultiReader(bytes.NewReader(wire.Bytes()), reader))
					request, err := http.ReadRequest(parser)
					if err != nil {
						return
					}
					captured.Body, err = io.ReadAll(request.Body)
					request.Body.Close()
					if err != nil {
						return
					}
					captured.Connection, captured.DidResume = id, resumed
					p.mu.Lock()
					p.requests = append(p.requests, captured)
					p.mu.Unlock()
					response, closeAfter := handler(ctx, captured)
					if _, err := io.WriteString(conn, response); err != nil || closeAfter {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		<-acceptDone
		connMu.Lock()
		for conn := range conns {
			conn.Close()
		}
		connMu.Unlock()
		wg.Wait()
	})
	return p
}

func h1Session(t *testing.T, peer *h1WirePeer, configure func(*Options)) *Session {
	t.Helper()
	options := Options{Profile: testProfile(t), RootCAs: peer.Roots, MaxConcurrentRequests: 64, MaxPendingRequests: 64}
	if configure != nil {
		configure(&options)
	}
	s, err := NewSession(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func h1Reply(body string) string {
	return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
}

func TestHTTP1ALPNFallbackPreservesCaseOrderDuplicatesAndReusesOneConnection(t *testing.T) {
	peer := newH1WirePeer(t, true, []string{"http/1.1"}, func(_ context.Context, req h1WireRequest) (string, bool) {
		body, _ := json.Marshal(req)
		return fmt.Sprintf("HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nX-Marker: between\r\nset-cookie: b=2\r\nContent-Length: %d\r\n\r\n%s", len(body), body), false
	})
	s := h1Session(t, peer, nil)
	headers := []HeaderField{{"Cookie", "a=1"}, {"X-Marker", "middle"}, {"cOOkie", "b=2"}}
	for range 2 {
		response, err := s.Do(testContext(t), Request{URL: peer.URL + "/wire?q=1", Headers: headers, HeadersOrder: []string{"Cookie", "X-MARKER", "COOKIE"}})
		if err != nil {
			t.Fatal(err)
		}
		if response.Protocol != "HTTP/1.1" {
			t.Fatalf("protocol=%s", response.Protocol)
		}
		var captured h1WireRequest
		if err := json.Unmarshal(response.Body, &captured); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(captured.Headers[:3], headers) {
			t.Fatalf("wire=%+v", captured.Headers)
		}
		if captured.Line != "GET /wire?q=1 HTTP/1.1" {
			t.Fatal(captured.Line)
		}
		want := []HeaderField{{"Set-Cookie", "a=1"}, {"X-Marker", "between"}, {"set-cookie", "b=2"}}
		if !reflect.DeepEqual(response.Headers[:3], want) {
			t.Fatalf("response=%+v", response.Headers)
		}
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.accepted != 1 || len(peer.hellos) != 1 || len(peer.requests) != 2 {
		t.Fatalf("connections=%d hellos=%d requests=%d", peer.accepted, len(peer.hellos), len(peer.requests))
	}
	if !reflect.DeepEqual(peer.hellos[0], []string{"h2", "http/1.1"}) {
		t.Fatalf("fallback changed original ALPN: %v", peer.hellos)
	}
}

func TestForceHTTP1AndPlainHTTP(t *testing.T) {
	for _, secure := range []bool{true, false} {
		t.Run(fmt.Sprint(secure), func(t *testing.T) {
			peer := newH1WirePeer(t, secure, []string{"h2", "http/1.1"}, func(_ context.Context, req h1WireRequest) (string, bool) { return h1Reply(string(req.Body)), false })
			s := h1Session(t, peer, func(o *Options) { o.ForceHTTP1 = true })
			for range 2 {
				response, err := s.Do(testContext(t), Request{Method: "POST", URL: peer.URL, Body: []byte{0, 1, 255}})
				if err != nil || !bytes.Equal(response.Body, []byte{0, 1, 255}) {
					t.Fatalf("response=%+v err=%v", response, err)
				}
			}
			peer.mu.Lock()
			defer peer.mu.Unlock()
			if peer.accepted != 1 {
				t.Fatalf("accepted %d connections", peer.accepted)
			}
			if secure && !reflect.DeepEqual(peer.hellos, [][]string{{"http/1.1"}}) {
				t.Fatalf("forced ALPN=%v", peer.hellos)
			}
		})
	}
}

func TestHTTP1ConcurrentSharedSessionKeepsRequestHeadersAndCookiesIsolated(t *testing.T) {
	const count = 24
	started := make(chan struct{}, count)
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	peer := newH1WirePeer(t, true, []string{"http/1.1"}, func(ctx context.Context, req h1WireRequest) (string, bool) {
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		body, _ := json.Marshal(req.Headers)
		return h1Reply(string(body)), false
	})
	s := h1Session(t, peer, nil)
	errorsCh := make(chan error, count)
	for i := range count {
		go func() {
			headers := []HeaderField{{"Cookie", fmt.Sprintf("first=%d", i)}, {"X-ID", fmt.Sprint(i)}, {"cookie", fmt.Sprintf("second=%d", i)}}
			order := []string{"cookie", "x-id", "cookie"}
			want := append([]HeaderField(nil), headers...)
			if i%2 != 0 {
				order = []string{"x-id", "cookie"}
				want = []HeaderField{headers[1], headers[0], headers[2]}
			}
			response, err := s.Do(testContext(t), Request{URL: peer.URL, Headers: headers, HeadersOrder: order})
			if err == nil {
				var actual []HeaderField
				err = json.Unmarshal(response.Body, &actual)
				if err == nil && !reflect.DeepEqual(actual[:3], want) {
					err = fmt.Errorf("request %d got %+v", i, actual)
				}
			}
			errorsCh <- err
		}()
	}
	for range count {
		await(t, started)
	}
	once.Do(func() { close(release) })
	for range count {
		if err := await(t, errorsCh); err != nil {
			t.Error(err)
		}
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if len(peer.requests) != count || peer.accepted != count {
		t.Fatalf("requests=%d connections=%d", len(peer.requests), peer.accepted)
	}
}

func TestHTTP1ChunkedInformationalResponsesAndReuse(t *testing.T) {
	peer := newH1WirePeer(t, false, nil, func(context.Context, h1WireRequest) (string, bool) {
		return "HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\nX-End: yes\r\n\r\n", false
	})
	s := h1Session(t, peer, nil)
	for range 3 {
		response, err := s.Do(testContext(t), Request{URL: peer.URL})
		if err != nil || string(response.Body) != "abcde" || response.StatusCode != 200 {
			t.Fatalf("response=%+v err=%v", response, err)
		}
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.accepted != 1 {
		t.Fatalf("chunked response prevented reuse: %d", peer.accepted)
	}
}

func TestHTTP1ReconnectResumesTLSAndConnectionCloseIsHonored(t *testing.T) {
	peer := newH1WirePeer(t, true, []string{"http/1.1"}, func(context.Context, h1WireRequest) (string, bool) {
		return "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok", true
	})
	s := h1Session(t, peer, nil)
	for range 2 {
		if _, err := s.Do(testContext(t), Request{URL: peer.URL}); err != nil {
			t.Fatal(err)
		}
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if len(peer.requests) != 2 || peer.requests[0].DidResume || !peer.requests[1].DidResume || peer.accepted != 2 {
		t.Fatalf("requests=%+v connections=%d", peer.requests, peer.accepted)
	}
}

func TestHTTP1LimitsMalformedResponsesAndCertificateValidation(t *testing.T) {
	for _, test := range []struct {
		name, response string
		limit          int64
		target         error
	}{
		{"size", h1Reply(strings.Repeat("x", 100)), 16, ErrResponseTooLarge},
		{"truncated", "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort", 1024, io.ErrUnexpectedEOF},
		{"conflicting lengths", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx", 1024, nil},
		{"ambiguous framing", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 1024, nil},
		{"header limit", "HTTP/1.1 200 OK\r\nX-Large: " + strings.Repeat("x", 70<<10) + "\r\n\r\n", 1024, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			peer := newH1WirePeer(t, false, nil, func(context.Context, h1WireRequest) (string, bool) { return test.response, true })
			s := h1Session(t, peer, func(o *Options) { o.MaxResponseBytes = test.limit })
			_, err := s.Do(testContext(t), Request{URL: peer.URL})
			if err == nil || test.target != nil && !errors.Is(err, test.target) {
				t.Fatalf("error=%v want=%v", err, test.target)
			}
		})
	}
	peer := newH1WirePeer(t, true, []string{"http/1.1"}, func(context.Context, h1WireRequest) (string, bool) { return h1Reply("ok"), false })
	s := h1Session(t, peer, func(o *Options) { o.RootCAs = x509.NewCertPool(); o.ForceHTTP1 = true })
	if _, err := s.Do(testContext(t), Request{URL: peer.URL}); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
}

func TestHTTP1NoALPNAndProtocolSpecificHeaders(t *testing.T) {
	for _, protocols := range [][]string{nil, {"http/1.1"}} {
		peer := newH1WirePeer(t, true, protocols, func(context.Context, h1WireRequest) (string, bool) { return h1Reply("ok"), false })
		s := h1Session(t, peer, nil)
		for range 2 {
			response, err := s.Do(testContext(t), Request{URL: peer.URL, Headers: []HeaderField{{"hOsT", "custom.test"}, {"Connection", "keep-alive"}}})
			if err != nil || response.Protocol != "HTTP/1.1" {
				t.Fatalf("response=%+v err=%v", response, err)
			}
		}
		peer.mu.Lock()
		if peer.accepted != 1 {
			t.Errorf("protocol-specific headers caused %d handshakes", peer.accepted)
		}
		if got := peer.requests[0].Headers; !reflect.DeepEqual(got, []HeaderField{{"hOsT", "custom.test"}, {"Connection", "keep-alive"}}) {
			t.Errorf("wire=%+v", got)
		}
		peer.mu.Unlock()
	}
}

func TestHTTP1RequestOrderIncludesGeneratedHostAndLength(t *testing.T) {
	peer := newH1WirePeer(t, false, nil, func(_ context.Context, req h1WireRequest) (string, bool) {
		body, _ := json.Marshal(req.Headers)
		return h1Reply(string(body)), false
	})
	s := h1Session(t, peer, nil)
	response, err := s.Do(testContext(t), Request{Method: "POST", URL: peer.URL, Body: []byte("abc"), Headers: []HeaderField{{"X-Test", "one"}}, HeadersOrder: []string{"HOST", "Content-Length", "x-test"}})
	if err != nil {
		t.Fatal(err)
	}
	var fields []HeaderField
	if err := json.Unmarshal(response.Body, &fields); err != nil {
		t.Fatal(err)
	}
	want := []HeaderField{{"Host", strings.TrimPrefix(peer.URL, "http://")}, {"Content-Length", "3"}, {"X-Test", "one"}}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf("headers=%+v want=%+v", fields, want)
	}
}

func TestHTTP1ALPNHandoffCanonicalizesDNSAuthorityCase(t *testing.T) {
	peer := newH1WirePeer(t, true, []string{"http/1.1"}, func(context.Context, h1WireRequest) (string, bool) { return h1Reply("ok"), false })
	s := h1Session(t, peer, func(o *Options) { o.InsecureSkipVerify = true })
	for _, host := range []string{"LOCALHOST", "localhost"} {
		response, err := s.Do(testContext(t), Request{URL: strings.Replace(peer.URL, "127.0.0.1", host, 1)})
		if err != nil || response.Protocol != "HTTP/1.1" {
			t.Fatalf("response=%+v err=%v", response, err)
		}
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if peer.accepted != 1 {
		t.Fatalf("DNS case prevented handoff/reuse: connections=%d", peer.accepted)
	}
}

func TestHTTP1CaptureCanHandOffItsOriginalTLSConnectionToH2(t *testing.T) {
	server := testServer(t, func(context.Context, testserver.Request) testserver.Response {
		return testserver.Response{Body: []byte("h2")}
	})
	var document map[string]any
	if err := json.Unmarshal([]byte(localProfile), &document); err != nil {
		t.Fatal(err)
	}
	document["http_version"] = "http/1.1"
	encoded, _ := json.Marshal(document)
	p, err := profile.Load(encoded)
	if err != nil {
		t.Fatal(err)
	}
	s := testSession(t, server, func(o *Options) { o.Profile = p })
	for range 2 {
		response, err := s.Do(testContext(t), Request{URL: server.URL, Headers: []HeaderField{{"X-Cased", "one"}, {"x-CASED", "two"}}})
		if err != nil || response.Protocol != "HTTP/2.0" {
			t.Fatalf("response=%+v err=%v", response, err)
		}
	}
	snapshot := server.Snapshot()
	if snapshot.Connections != 1 || len(snapshot.ClientHellos) != 1 {
		t.Fatalf("handoff redialed: %+v", snapshot)
	}
	var values []string
	for _, field := range snapshot.Requests[0].Headers {
		if field.Name == "x-cased" {
			values = append(values, field.Value)
		}
	}
	if !reflect.DeepEqual(values, []string{"one", "two"}) {
		t.Fatalf("H2 did not normalize case/retain duplicates: %v", values)
	}
}

func TestHTTP1AmbiguousFailureNeverReplaysRequest(t *testing.T) {
	peer := newH1WirePeer(t, true, []string{"http/1.1"}, func(_ context.Context, req h1WireRequest) (string, bool) {
		if string(req.Body) == "first" {
			return "", true
		}
		return h1Reply("ok"), false
	})
	s := h1Session(t, peer, func(o *Options) { o.MaxUnprocessedRetries = 32 })
	if _, err := s.Do(testContext(t), Request{Method: "POST", URL: peer.URL, Body: []byte("first")}); err == nil {
		t.Fatal("request without response succeeded")
	}
	peer.mu.Lock()
	count, connections := len(peer.requests), peer.accepted
	peer.mu.Unlock()
	if count != 1 || connections != 1 {
		t.Fatalf("ambiguous request was replayed: requests=%d connections=%d", count, connections)
	}
	if _, err := s.Do(testContext(t), Request{URL: peer.URL}); err != nil {
		t.Fatalf("explicit next request failed: %v", err)
	}
}

func TestHTTP1DoesNotDrainStalledBytesAfterContentDecoderEOF(t *testing.T) {
	var compressed bytes.Buffer
	writer := zlib.NewWriter(&compressed)
	writer.Write([]byte("decoded"))
	writer.Close()
	peer := newH1WirePeer(t, false, nil, func(context.Context, h1WireRequest) (string, bool) {
		return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\nContent-Length: %d\r\n\r\n%s", compressed.Len()+100, compressed.Bytes()), false
	})
	s := h1Session(t, peer, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := s.Do(ctx, Request{URL: peer.URL})
	if err == nil || errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "content decoder") {
		t.Fatalf("decoder completion drained/stalled incomplete HTTP body: %v", err)
	}
}

func TestHTTP1CancellationTimeoutAndSessionCloseInterruptIO(t *testing.T) {
	for _, action := range []string{"cancel", "timeout", "close"} {
		t.Run(action, func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			defer close(release)
			peer := newH1WirePeer(t, false, nil, func(ctx context.Context, req h1WireRequest) (string, bool) {
				close(started)
				select {
				case <-release:
				case <-ctx.Done():
				}
				return h1Reply("late"), false
			})
			s := h1Session(t, peer, nil)
			ctx, cancel := context.WithCancel(context.Background())
			if action == "timeout" {
				ctx, cancel = context.WithTimeout(context.Background(), 80*time.Millisecond)
			}
			defer cancel()
			errorsCh := make(chan error, 1)
			go func() { _, err := s.Do(ctx, Request{URL: peer.URL}); errorsCh <- err }()
			await(t, started)
			want := context.Canceled
			switch action {
			case "cancel":
				cancel()
			case "timeout":
				want = context.DeadlineExceeded
			case "close":
				s.Close()
				want = ErrSessionClosed
			}
			if err := await(t, errorsCh); !errors.Is(err, want) {
				t.Fatalf("error=%v want=%v", err, want)
			}
			s.mu.Lock()
			active := len(s.connections)
			s.mu.Unlock()
			if active != 0 {
				t.Fatalf("leaked %d connections", active)
			}
		})
	}
}

func TestHTTP1ProxyAuthenticationStaysOutsideOriginAndTunnelReuses(t *testing.T) {
	peer := newH1WirePeer(t, true, []string{"http/1.1"}, func(context.Context, h1WireRequest) (string, bool) { return h1Reply("ok"), false })
	connects := make(chan string, 2)
	proxy := localProxy(t, func(client net.Conn) {
		reader := bufio.NewReader(client)
		request, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		connects <- request.Header.Get("Proxy-Authorization")
		upstream, err := net.Dial("tcp", request.Host)
		if err != nil {
			return
		}
		defer upstream.Close()
		io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		done := make(chan struct{})
		go func() { io.Copy(upstream, reader); upstream.Close(); close(done) }()
		io.Copy(client, upstream)
		client.Close()
		<-done
	})
	s := h1Session(t, peer, func(o *Options) { o.ProxyURL = proxy; o.ProxyAuth = &ProxyAuth{Username: "user", Password: "secret"} })
	for range 2 {
		if _, err := s.Do(testContext(t), Request{URL: peer.URL}); err != nil {
			t.Fatal(err)
		}
	}
	if got := await(t, connects); got != "Basic "+base64.StdEncoding.EncodeToString([]byte("user:secret")) {
		t.Fatalf("CONNECT auth=%q", got)
	}
	select {
	case <-connects:
		t.Fatal("second request opened another CONNECT tunnel")
	default:
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	for _, req := range peer.requests {
		for _, field := range req.Headers {
			if strings.EqualFold(field.Name, "Proxy-Authorization") {
				t.Fatal("proxy credentials reached origin")
			}
		}
	}
}
