package requestsutls

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// CONNECT fixture is loopback-only and never consumes machine proxy settings.
// Fixed lifetime is measured once after CONNECT, never refreshed by traffic.
func lifetimeProxy(t *testing.T, lifetime time.Duration) (string, *atomic.Int64) {
	t.Helper()
	var connects atomic.Int64
	proxy := localProxy(t, func(client net.Conn) {
		reader := bufio.NewReader(client)
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		host, _, err := net.SplitHostPort(req.Host)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return
		}
		upstream, err := net.DialTimeout("tcp", req.Host, time.Second)
		if err != nil {
			return
		}
		defer upstream.Close()
		connects.Add(1)
		fmt.Fprint(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		if lifetime > 0 {
			timer := time.AfterFunc(lifetime, func() {
				// Half-close sends FIN while the copy loop continues draining client data.
				client.(*net.TCPConn).CloseWrite()
			})
			defer timer.Stop()
		}
		done := make(chan struct{})
		go func() { io.Copy(upstream, reader); upstream.Close(); close(done) }()
		io.Copy(client, upstream)
		client.Close()
		<-done
	})
	return proxy, &connects
}

func lifetimeSession(t *testing.T, h1 bool, age time.Duration, handler http.HandlerFunc) (*Session, string, *atomic.Int64) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = !h1
	server.StartTLS()
	t.Cleanup(server.Close)
	proxy, connects := lifetimeProxy(t, 0)
	s, err := NewSession(Options{Profile: testProfile(t), InsecureSkipVerify: true, ForceHTTP1: h1, ProxyURL: proxy, MaxConnectionAge: age, MaxConcurrentRequests: 64, MaxPendingRequests: 64})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, server.URL, connects
}

func waitConnectionDeadline(t *testing.T, s *Session) *trackedConn {
	t.Helper()
	s.mu.Lock()
	var conn *trackedConn
	for c := range s.connections {
		conn = c
		break
	}
	s.mu.Unlock()
	if conn == nil || conn.retireAt.IsZero() {
		t.Fatal("missing physical connection deadline")
	}
	time.Sleep(max(0, time.Until(conn.retireAt)) + time.Millisecond)
	return conn
}

func waitConnectionClosed(t *testing.T, s *Session, conn *trackedConn) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		_, exists := s.connections[conn]
		s.mu.Unlock()
		if !exists {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("draining connection leaked")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestConnectionLifetimeSlowBodyAndPOST(t *testing.T) {
	for _, h1 := range []bool{false, true} {
		t.Run(fmt.Sprint("h1=", h1), func(t *testing.T) {
			started, release := make(chan string, 1), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			var mu sync.Mutex
			seen := map[string]int{}
			s, url, connects := lifetimeSession(t, h1, 200*time.Millisecond, func(w http.ResponseWriter, r *http.Request) {
				id := r.Header.Get("X-Request-ID")
				mu.Lock()
				seen[id]++
				mu.Unlock()
				if id == "slow" {
					w.Write([]byte("first"))
					w.(http.Flusher).Flush()
					started <- r.RemoteAddr
					<-release
					w.Write([]byte("last"))
				} else {
					fmt.Fprint(w, r.RemoteAddr)
				}
			})
			ctx := testContext(t)
			done := make(chan error, 1)
			go func() {
				res, err := s.Do(ctx, Request{Method: "POST", URL: url, Headers: []HeaderField{{"X-Request-ID", "slow"}}, Body: []byte("unique")})
				if err == nil && string(res.Body) != "firstlast" {
					err = fmt.Errorf("truncated body: %q", res.Body)
				}
				done <- err
			}()
			oldAddr := await(t, started)
			old := waitConnectionDeadline(t, s)
			for i := 0; i < 3; i++ {
				res, err := s.Do(ctx, Request{Method: "POST", URL: url, Headers: []HeaderField{{"X-Request-ID", fmt.Sprint(i)}}, Body: []byte("unique")})
				if err != nil {
					t.Fatal(err)
				}
				if string(res.Body) == oldAddr {
					t.Fatal("expired physical connection reused")
				}
			}
			s.mu.Lock()
			_, alive := s.connections[old]
			s.mu.Unlock()
			if !alive {
				t.Fatal("slow response body connection closed early")
			}
			once.Do(func() { close(release) })
			if err := await(t, done); err != nil {
				t.Fatal(err)
			}
			waitConnectionClosed(t, s, old)
			if connects.Load() != 2 {
				t.Fatalf("got %d CONNECTs, want 2", connects.Load())
			}
			mu.Lock()
			defer mu.Unlock()
			for id, n := range seen {
				if n != 1 {
					t.Fatalf("POST %s executed %d times", id, n)
				}
			}
			if len(seen) != 4 {
				t.Fatalf("requests: %v", seen)
			}
		})
	}
}

func TestConnectionLifetimeDefaultAndRepeatedReuse(t *testing.T) {
	for _, h1 := range []bool{false, true} {
		for _, age := range []time.Duration{0, 80 * time.Millisecond} {
			t.Run(fmt.Sprintf("h1=%v/age=%s", h1, age), func(t *testing.T) {
				s, url, connects := lifetimeSession(t, h1, age, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r.RemoteAddr) })
				ctx := testContext(t)
				previous := ""
				for cycle := 0; cycle < 4; cycle++ {
					var current string
					for i := 0; i < 3; i++ {
						res, err := s.Do(ctx, Request{URL: url})
						if err != nil {
							t.Fatal(err)
						}
						if i > 0 && current != string(res.Body) {
							t.Fatal("lost reuse within lifetime")
						}
						current = string(res.Body)
					}
					if cycle > 0 && ((age == 0 && current != previous) || (age > 0 && current == previous)) {
						t.Fatal("incorrect physical connection rotation")
					}
					previous = current
					if age > 0 {
						waitConnectionDeadline(t, s)
					} else {
						time.Sleep(80 * time.Millisecond)
					}
				}
				want := int64(4)
				if age == 0 {
					want = 1
				}
				if connects.Load() != want {
					t.Fatalf("CONNECTs=%d want %d", connects.Load(), want)
				}
				s.Close()
				s.mu.Lock()
				defer s.mu.Unlock()
				if len(s.connections) != 0 {
					t.Fatal("connections remain after Close")
				}
			})
		}
	}
}

func TestConnectionLifetimeJitterAndValidation(t *testing.T) {
	for _, o := range []Options{{MaxConnectionAge: -1}, {ConnectionAgeJitter: 1}, {MaxConnectionAge: 1, ConnectionAgeJitter: 1}, {MaxConnectionAge: 2, ConnectionAgeJitter: -1}} {
		o.Profile = testProfile(t)
		if s, err := NewSession(o); err == nil {
			s.Close()
			t.Fatal("invalid lifetime accepted")
		}
	}
	s, err := NewSession(Options{Profile: testProfile(t), MaxConnectionAge: time.Second, ConnectionAgeJitter: time.Second / 2})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	distinct := map[time.Duration]bool{}
	for range 100 {
		created, retire := s.newConnectionLifetime()
		age := retire.Sub(created)
		if age <= time.Second/2 || age > time.Second {
			t.Fatal(age)
		}
		distinct[age] = true
	}
	if len(distinct) < 2 {
		t.Fatal("jitter not sampled independently")
	}
}

func TestConnectionLifetimeHandshakeAlreadyExpired(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("expired connection sent request") }))
	defer server.Close()
	s, err := NewSession(Options{Profile: testProfile(t), InsecureSkipVerify: true, MaxConnectionAge: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = s.Do(testContext(t), Request{URL: server.URL})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("got %v", err)
	}
}

func TestConnectionLifetimeProxyFixedFINBaseline(t *testing.T) {
	for _, h1 := range []bool{false, true} {
		t.Run(fmt.Sprint(h1), func(t *testing.T) {
			started := make(chan struct{}, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("first"))
				w.(http.Flusher).Flush()
				started <- struct{}{}
				<-r.Context().Done()
			}))
			server.EnableHTTP2 = !h1
			server.StartTLS()
			defer server.Close()
			proxy, count := lifetimeProxy(t, 150*time.Millisecond)
			s, err := NewSession(Options{Profile: testProfile(t), ForceHTTP1: h1, InsecureSkipVerify: true, ProxyURL: proxy})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err = s.Do(ctx, Request{URL: server.URL})
			if err == nil || ctx.Err() != nil {
				t.Fatalf("want transport EOF before deadline, got %v", err)
			}
			if count.Load() != 1 {
				t.Fatal("ambiguous failure replayed")
			}
			await(t, started)
		})
	}
}

// Opt-in 100-second loopback tunnel test. No external targets or credentials.
// RUTS_LIFETIME_LONG=1 go test -run TestConnectionLifetimeLongProxy -timeout 8m
func TestConnectionLifetimeLongProxy(t *testing.T) {
	if os.Getenv("RUTS_LIFETIME_LONG") != "1" {
		t.Skip("set RUTS_LIFETIME_LONG=1 for three 100-second tunnel cycles")
	}
	for _, h1 := range []bool{false, true} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("h1=%v/enabled=%v", h1, enabled), func(t *testing.T) {
				t.Parallel()
				var calls sync.Map
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/slow" {
						id := r.Header.Get("X-Request-ID")
						if _, loaded := calls.LoadOrStore(id, true); loaded {
							t.Errorf("POST %s replayed", id)
						}
						w.Write([]byte("start"))
						w.(http.Flusher).Flush()
						select {
						case <-time.After(20 * time.Second):
							fmt.Fprint(w, "end")
						case <-r.Context().Done():
						}
					} else {
						fmt.Fprint(w, r.RemoteAddr)
					}
				}))
				server.EnableHTTP2 = !h1
				server.StartTLS()
				t.Cleanup(server.Close)
				proxy, connects := lifetimeProxy(t, 100*time.Second)
				age, jitter := time.Duration(0), time.Duration(0)
				if enabled {
					age = 60 * time.Second
					jitter = 10 * time.Second
				}
				s, err := NewSession(Options{Profile: testProfile(t), ForceHTTP1: h1, InsecureSkipVerify: true, ProxyURL: proxy, MaxConnectionAge: age, ConnectionAgeJitter: jitter})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { s.Close() })
				failures := 0
				for cycle := 0; cycle < 3; cycle++ {
					start := time.Now()
					// Traffic keeps idle cleanup from hiding the proxy's absolute lifetime.
					for time.Since(start) < 90*time.Second {
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						_, err := s.Do(ctx, Request{URL: server.URL})
						cancel()
						if err != nil {
							t.Fatalf("warm traffic: %v", err)
						}
						time.Sleep(2 * time.Second)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					res, err := s.Do(ctx, Request{Method: "POST", URL: server.URL + "/slow", Headers: []HeaderField{{"X-Request-ID", fmt.Sprint(cycle)}}})
					cancel()
					if err != nil {
						failures++
					} else if string(res.Body) != "startend" {
						t.Fatalf("truncated body %q", res.Body)
					}
					if enabled && err != nil {
						t.Fatal(err)
					}
					t.Logf("cycle=%d enabled=%v elapsed=%s CONNECTs=%d error=%v", cycle, enabled, time.Since(start), connects.Load(), err)
				}
				if !enabled && failures != 3 {
					t.Fatalf("baseline failed %d times, want 3", failures)
				}
			})
		}
	}
}

func TestConnectionLifetimeConcurrentReplacementAndClose(t *testing.T) {
	hold, started := make(chan struct{}), make(chan struct{}, 64)
	var once sync.Once
	defer once.Do(func() { close(hold) })
	s, url, connects := lifetimeSession(t, false, 200*time.Millisecond, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			started <- struct{}{}
			select {
			case <-hold:
			case <-r.Context().Done():
				return
			}
		}
		fmt.Fprint(w, r.RemoteAddr)
	})
	ctx := testContext(t)
	if _, err := s.Do(ctx, Request{URL: url}); err != nil {
		t.Fatal(err)
	}
	old := waitConnectionDeadline(t, s)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			_, err := s.Do(ctx, Request{URL: url + "/hold"})
			if err != nil {
				t.Error(err)
			}
		})
	}
	for range 32 {
		await(t, started)
	}
	if connects.Load() != 2 {
		t.Fatalf("replacement dial storm: %d", connects.Load())
	}
	waitConnectionClosed(t, s, old)
	once.Do(func() { close(hold) })
	wg.Wait()
	for range 8 {
		wg.Go(func() { s.Close() })
	}
	wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.connections) != 0 {
		t.Fatal("sockets remain after concurrent Close")
	}
}

func TestConnectionLifetimeCancellationKeepsSiblingStream(t *testing.T) {
	started, release := make(chan struct{}, 4), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	s, url, _ := lifetimeSession(t, false, 200*time.Millisecond, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			w.Write([]byte("first"))
			w.(http.Flusher).Flush()
			started <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		fmt.Fprint(w, "last")
	})
	ctx := testContext(t)
	cancelled, cancel := context.WithCancel(ctx)
	defer cancel()
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { _, err := s.Do(cancelled, Request{URL: url + "/hold"}); first <- err }()
	await(t, started)
	go func() {
		res, err := s.Do(ctx, Request{URL: url + "/hold"})
		if err == nil && string(res.Body) != "firstlast" {
			err = fmt.Errorf("truncated sibling")
		}
		second <- err
	}()
	await(t, started)
	old := waitConnectionDeadline(t, s)
	if _, err := s.Do(ctx, Request{URL: url}); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := await(t, first); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	s.mu.Lock()
	_, exists := s.connections[old]
	s.mu.Unlock()
	if !exists {
		t.Fatal("cancel closed sibling socket")
	}
	once.Do(func() { close(release) })
	if err := await(t, second); err != nil {
		t.Fatal(err)
	}
	waitConnectionClosed(t, s, old)
}

func TestConnectionLifetimeHTTP1FallbackAndPlain(t *testing.T) {
	for _, plain := range []bool{false, true} {
		t.Run(fmt.Sprint("plain=", plain), func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r.RemoteAddr) })
			server := httptest.NewUnstartedServer(handler)
			if plain {
				server.Start()
			} else {
				server.StartTLS()
			}
			t.Cleanup(server.Close)
			s, err := NewSession(Options{Profile: testProfile(t), InsecureSkipVerify: true, MaxConnectionAge: 80 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			first, err := s.Do(testContext(t), Request{URL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			if first.Protocol != "HTTP/1.1" {
				t.Fatal(first.Protocol)
			}
			old := waitConnectionDeadline(t, s)
			second, err := s.Do(testContext(t), Request{URL: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			if string(first.Body) == string(second.Body) {
				t.Fatal("fallback reused expired socket")
			}
			waitConnectionClosed(t, s, old)
		})
	}
}

func TestConnectionLifetimeReplacementDeadline(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	t.Cleanup(server.Close)
	var connects atomic.Int64
	release, blocked := make(chan struct{}), make(chan struct{}, 1)
	defer close(release)
	proxy := localProxy(t, func(client net.Conn) {
		reader := bufio.NewReader(client)
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		if connects.Add(1) > 1 {
			blocked <- struct{}{}
			<-release
			return
		}
		upstream, err := net.Dial("tcp", req.Host)
		if err != nil {
			return
		}
		defer upstream.Close()
		fmt.Fprint(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		done := make(chan struct{})
		go func() { io.Copy(upstream, reader); upstream.Close(); close(done) }()
		io.Copy(client, upstream)
		client.Close()
		<-done
	})
	s, err := NewSession(Options{Profile: testProfile(t), InsecureSkipVerify: true, ProxyURL: proxy, MaxConnectionAge: 80 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if _, err := s.Do(testContext(t), Request{URL: server.URL}); err != nil {
		t.Fatal(err)
	}
	waitConnectionDeadline(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = s.Do(ctx, Request{URL: server.URL})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 300*time.Millisecond {
		t.Fatal("replacement extended original deadline")
	}
	await(t, blocked)
	if connects.Load() != 2 {
		t.Fatal("replacement repeated failed dial")
	}
	s.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.connections) != 0 {
		t.Fatal("failed replacement leaked socket")
	}
}

func TestConnectionLifetimeIndependentOrigins(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r.RemoteAddr) })
	a, b := httptest.NewTLSServer(handler), httptest.NewTLSServer(handler)
	defer a.Close()
	defer b.Close()
	s, err := NewSession(Options{Profile: testProfile(t), InsecureSkipVerify: true, MaxConnectionAge: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	request := func(url string) string {
		t.Helper()
		res, err := s.Do(testContext(t), Request{URL: url})
		if err != nil {
			t.Fatal(err)
		}
		return string(res.Body)
	}
	firstA := request(a.URL)
	s.mu.Lock()
	var oldA *trackedConn
	for c := range s.connections {
		oldA = c
	}
	s.mu.Unlock()
	time.Sleep(180 * time.Millisecond)
	firstB := request(b.URL)
	time.Sleep(max(0, time.Until(oldA.retireAt)) + time.Millisecond)
	if request(a.URL) == firstA {
		t.Fatal("origin A did not rotate")
	}
	if request(b.URL) != firstB {
		t.Fatal("origin B inherited origin A age")
	}
	waitConnectionClosed(t, s, oldA)
}

func TestConnectionLifetimeCannotProtectOverlongBody(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("partial"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	proxy, count := lifetimeProxy(t, 150*time.Millisecond)
	s, err := NewSession(Options{Profile: testProfile(t), InsecureSkipVerify: true, ProxyURL: proxy, MaxConnectionAge: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = s.Do(ctx, Request{Method: "POST", URL: server.URL, Body: []byte("once")})
	if err == nil || ctx.Err() != nil {
		t.Fatalf("want original transport failure, got %v", err)
	}
	if count.Load() != 1 {
		t.Fatal("overlong POST replayed on another connection")
	}
}
