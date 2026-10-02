package requestsutls

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chuu3/requests-utls/profile"
)

func timeoutSession(t *testing.T, change func(*Options)) *Session {
	t.Helper()
	p, err := profile.LoadFile("profiles/chrome_152.json")
	if err != nil {
		t.Fatal(err)
	}
	o := Options{Profile: p, InsecureSkipVerify: true}
	change(&o)
	s, err := NewSession(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func assertStageTimeout(t *testing.T, err error, stage string) {
	t.Helper()
	var got *StageError
	if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &got) || got.Stage != stage || got.Elapsed <= 0 {
		t.Fatalf("want %s timeout, got %#v (%v)", stage, got, err)
	}
}
func TestResponsePhaseTimeoutsAndReuse(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, phase := range []string{"response_headers", "body"} {
			t.Run(fmt.Sprintf("h2=%v/%s", h2, phase), func(t *testing.T) {
				release := make(chan struct{})
				peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/ok" {
						w.Write([]byte("ok"))
						return
					}
					if phase == "body" {
						w.Header().Set("Content-Length", "10")
						w.WriteHeader(200)
						w.(http.Flusher).Flush()
					}
					select {
					case <-r.Context().Done():
					case <-release:
					}
				}))
				var connections atomic.Int32
				peer.Config.ConnState = func(_ net.Conn, state http.ConnState) {
					if state == http.StateNew {
						connections.Add(1)
					}
				}
				peer.EnableHTTP2 = h2
				peer.StartTLS()
				defer peer.Close()
				defer close(release)
				s := timeoutSession(t, func(o *Options) {
					o.ForceHTTP1 = !h2
					if phase == "body" {
						o.BodyTimeout = 60 * time.Millisecond
					} else {
						o.ResponseHeaderTimeout = 60 * time.Millisecond
					}
				})
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				// Warm the connection, so the phase test excludes handshake latency.
				if _, err := s.Do(ctx, Request{URL: peer.URL + "/ok"}); err != nil {
					t.Fatal(err)
				}
				_, err := s.Do(ctx, Request{URL: peer.URL + "/slow"})
				assertStageTimeout(t, err, phase)
				if r, err := s.Do(ctx, Request{URL: peer.URL + "/ok"}); err != nil || string(r.Body) != "ok" {
					t.Fatalf("after timeout: %v", err)
				}
				if h2 && connections.Load() != 1 {
					t.Fatalf("stream timeout closed shared connection: %d connections", connections.Load())
				}
			})
		}
	}
}
func TestTLSPhaseTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		<-done
	}()
	s := timeoutSession(t, func(o *Options) { o.TLSHandshakeTimeout = 60 * time.Millisecond })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = s.Do(ctx, Request{URL: "https://" + listener.Addr().String()})
	assertStageTimeout(t, err, "tls")
}
func TestProxyPhaseTimeout(t *testing.T) {
	release := make(chan struct{})
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer proxy.Close()
	defer close(release)
	s := timeoutSession(t, func(o *Options) { o.ProxyURL = proxy.URL; o.ProxyConnectTimeout = 60 * time.Millisecond })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := s.Do(ctx, Request{URL: "https://example.test/"})
	assertStageTimeout(t, err, "proxy_connect")
}
func TestSocketDeadlineNormalizesBeforeContextTimer(t *testing.T) {
	// Socket timers can fire before ctx.Err() observes the same deadline.
	s := &Session{ctx: context.Background()}
	err := s.requestError(context.Background(), &net.OpError{Op: "read", Err: timeoutNetError{}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "i/o timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

func TestTotalDeadlineBoundsPhaseTimeout(t *testing.T) {
	release := make(chan struct{})
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer peer.Close()
	defer close(release)
	s := timeoutSession(t, func(o *Options) { o.ResponseHeaderTimeout = 5 * time.Second })
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	_, err := s.Do(ctx, Request{URL: peer.URL})
	assertStageTimeout(t, err, "response_headers")
}
func TestPhaseTimeoutOptionsRejectNegative(t *testing.T) {
	p, err := profile.LoadFile("profiles/chrome_152.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, set := range []func(*Options){
		func(o *Options) { o.ConnectTimeout = -1 }, func(o *Options) { o.ProxyConnectTimeout = -1 },
		func(o *Options) { o.TLSHandshakeTimeout = -1 }, func(o *Options) { o.ResponseHeaderTimeout = -1 }, func(o *Options) { o.BodyTimeout = -1 },
	} {
		o := Options{Profile: p}
		set(&o)
		if s, err := NewSession(o); err == nil {
			s.Close()
			t.Fatal("negative phase timeout accepted")
		}
	}
}

func TestProxyFailureIsNotCancellation(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(502) }))
	defer proxy.Close()
	s := timeoutSession(t, func(o *Options) { o.ProxyURL = proxy.URL })
	_, err := s.Do(context.Background(), Request{URL: "https://example.test/"})
	var staged *StageError
	if !errors.As(err, &staged) || staged.Stage != "proxy_connect" || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wrong proxy classification: %v", err)
	}
}
func TestConnectFailureStage(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	s := timeoutSession(t, func(o *Options) {})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = s.Do(ctx, Request{URL: "http://" + addr})
	var staged *StageError
	if !errors.As(err, &staged) || staged.Stage != "connect" {
		t.Fatalf("wrong connect classification: %v", err)
	}
}
func TestQueueTimeoutStage(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-release; w.Write([]byte("ok")) }))
	defer peer.Close()
	defer close(release)
	s := timeoutSession(t, func(o *Options) { o.MaxConcurrentRequests = 1; o.MaxPendingRequests = 1 })
	first := make(chan error, 1)
	go func() { _, err := s.Do(context.Background(), Request{URL: peer.URL}); first <- err }()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	_, err := s.Do(ctx, Request{URL: peer.URL})
	assertStageTimeout(t, err, "queue")
	s.Close()
	if err := <-first; !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("close: %v", err)
	}
}

func TestProxyResponseErrorBeforeContextDeadline(t *testing.T) {
	// Reproduce the socket timer firing before ctx.Err() without a timing race.
	err := proxyResponseError(&net.OpError{Op: "read", Err: timeoutNetError{}})
	wrapped := stageError(context.Background(), "proxy_connect", time.Now(), err)
	assertStageTimeout(t, wrapped, "proxy_connect")
}

func TestProxyResponseErrorDoesNotReflectResponse(t *testing.T) {
	err := proxyResponseError(errors.New("malformed HTTP response: private-proxy-value"))
	if err.Error() != "requests-utls: proxy CONNECT received an invalid or oversized HTTP response" {
		t.Fatalf("unexpected sanitized error: %v", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("malformed response was classified as a timeout")
	}
}
