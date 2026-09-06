package requestsutls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	utls "github.com/refraction-networking/utls"
	"github.com/chuu3/requests-utls/profile"
)

type resumptionCaptureConn struct {
	net.Conn
	wire      []byte
	capturing bool
}

func (c *resumptionCaptureConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.capturing {
		c.wire = append(c.wire, p[:n]...)
	}
	return n, err
}

type resumptionListener struct{ net.Listener }

func (l resumptionListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &resumptionCaptureConn{Conn: c, capturing: true}, nil
}

type resumptionResult struct {
	Resumed    bool
	Connection string
}

type resumptionPeer struct {
	server   *httptest.Server
	hellos   chan []byte
	attempts atomic.Int32
}

func newResumptionPeer(t *testing.T, configure func(*tls.Config, int32)) *resumptionPeer {
	t.Helper()
	p := &resumptionPeer{hellos: make(chan []byte, 128)}
	p.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(resumptionResult{Resumed: r.TLS.DidResume, Connection: r.RemoteAddr})
	}))
	p.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	p.server.Listener = resumptionListener{p.server.Listener}
	p.server.EnableHTTP2 = true
	p.server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
	p.server.TLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		c := hello.Conn.(*resumptionCaptureConn)
		c.capturing = false
		p.hellos <- append([]byte(nil), c.wire...)
		attempt := p.attempts.Add(1)
		if configure == nil {
			return nil, nil
		}
		config := p.server.TLS.Clone()
		config.GetConfigForClient = nil
		configure(config, attempt)
		return config, nil
	}
	// Keep ticket keys stable across cloned configurations and both ports.
	var ticketKey [32]byte
	for i := range ticketKey {
		ticketKey[i] = byte(i + 1)
	}
	p.server.TLS.SetSessionTicketKeys([][32]byte{ticketKey})
	p.server.StartTLS()
	t.Cleanup(p.server.Close)
	return p
}

func (p *resumptionPeer) session(t *testing.T, configure func(*Options)) *Session {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(p.server.Certificate())
	o := Options{Profile: testProfile(t), RootCAs: roots}
	if configure != nil {
		configure(&o)
	}
	s, err := NewSession(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func resumedGet(t *testing.T, s *Session, url string) resumptionResult {
	t.Helper()
	r, err := s.Do(testContext(t), Request{Method: "GET", URL: url})
	if err != nil {
		t.Fatal(err)
	}
	var got resumptionResult
	if err := json.Unmarshal(r.Body, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func assertPSK(t *testing.T, wire []byte, want bool) helloFields {
	t.Helper()
	hello := parseHello(t, wire)
	if got := slices.Contains(hello.extensions, uint16(41)); got != want {
		t.Fatalf("pre_shared_key present=%v, want %v; extensions=%v", got, want, hello.extensions)
	}
	if want && hello.extensions[len(hello.extensions)-1] != 41 {
		t.Fatalf("pre_shared_key is not last: %v", hello.extensions)
	}
	return hello
}

func TestTLSResumptionAndConnectionReuse(t *testing.T) {
	p := newResumptionPeer(t, nil)
	s := p.session(t, nil)
	first := resumedGet(t, s, p.server.URL)
	cold := assertPSK(t, await(t, p.hellos), false)
	if first.Resumed {
		t.Fatal("first connection unexpectedly resumed")
	}
	if want := []uint16{10, 13, 16, 43, 51, 45}; !reflect.DeepEqual(cold.extensions, want) {
		t.Fatalf("first handshake profile changed: %v", cold.extensions)
	}
	second := resumedGet(t, s, p.server.URL)
	if second.Connection != first.Connection || second.Resumed || p.attempts.Load() != 1 {
		t.Fatalf("persistent HTTP/2 connection was not reused: first=%+v second=%+v", first, second)
	}
	s.transport.CloseIdleConnections()
	third := resumedGet(t, s, p.server.URL)
	resumed := assertPSK(t, await(t, p.hellos), true)
	if !third.Resumed || third.Connection == first.Connection {
		t.Fatalf("new connection did not actually resume: first=%+v third=%+v", first, third)
	}
	if !reflect.DeepEqual(resumed.extensions[:len(resumed.extensions)-1], cold.extensions) || !reflect.DeepEqual(resumed.ciphers, cold.ciphers) {
		t.Fatal("resumption changed non-PSK extension or cipher order")
	}
	// The same profile on another Session starts cold even with the same server.
	other := p.session(t, nil)
	if got := resumedGet(t, other, p.server.URL); got.Resumed {
		t.Fatal("ticket leaked across Sessions")
	}
	assertPSK(t, await(t, p.hellos), false)
}

func TestTLSResumptionDisabledAndMissingModes(t *testing.T) {
	for _, mode := range []string{"disabled", "missing_modes"} {
		t.Run(mode, func(t *testing.T) {
			p := newResumptionPeer(t, nil)
			s := p.session(t, func(o *Options) {
				if mode == "disabled" {
					o.DisableSessionResumption = true
					return
				}
				data := strings.Replace(localProfile, `,{"type":"psk_key_exchange_modes","values":[1]}`, "", 1)
				// Keep whitespace-independent fixture editing explicit.
				data = strings.Replace(data, ",\n      {\"type\":\"psk_key_exchange_modes\",\"values\":[1]}", "", 1)
				var err error
				o.Profile, err = profile.Load([]byte(data))
				if err != nil {
					t.Fatal(err)
				}
			})
			for range 2 {
				if got := resumedGet(t, s, p.server.URL); got.Resumed {
					t.Fatal("unexpected TLS resumption")
				}
				assertPSK(t, await(t, p.hellos), false)
				s.transport.CloseIdleConnections()
			}
		})
	}
}

func TestTLSResumptionAuthorityIsolation(t *testing.T) {
	first, second := newResumptionPeer(t, nil), newResumptionPeer(t, nil)
	s := first.session(t, func(o *Options) { o.RootCAs.AddCert(second.server.Certificate()) })
	resumedGet(t, s, first.server.URL)
	assertPSK(t, await(t, first.hellos), false)
	if got := resumedGet(t, s, second.server.URL); got.Resumed {
		t.Fatal("ticket leaked across ports")
	}
	assertPSK(t, await(t, second.hellos), false)
	s.transport.CloseIdleConnections()
	if got := resumedGet(t, s, second.server.URL); !got.Resumed {
		t.Fatal("second origin did not cache its own ticket")
	}
	assertPSK(t, await(t, second.hellos), true)
}

func TestTLSResumptionRejectedTicketFallsBackWithinHandshake(t *testing.T) {
	p := newResumptionPeer(t, func(config *tls.Config, attempt int32) {
		if attempt >= 2 {
			var newKey [32]byte
			newKey[0] = 100
			config.SetSessionTicketKeys([][32]byte{newKey})
		}
	})
	s := p.session(t, nil)
	resumedGet(t, s, p.server.URL)
	assertPSK(t, await(t, p.hellos), false)
	s.transport.CloseIdleConnections()
	if got := resumedGet(t, s, p.server.URL); got.Resumed {
		t.Fatal("server accepted a ticket encrypted under a retired key")
	}
	assertPSK(t, await(t, p.hellos), true)
	if p.attempts.Load() != 2 {
		t.Fatal("ticket rejection unnecessarily opened another connection")
	}
	s.transport.CloseIdleConnections()
	if got := resumedGet(t, s, p.server.URL); !got.Resumed {
		t.Fatal("replacement ticket was not cached")
	}
	assertPSK(t, await(t, p.hellos), true)
}

func TestTLSResumptionHelloRetryRequestFallback(t *testing.T) {
	p := newResumptionPeer(t, func(config *tls.Config, attempt int32) {
		if attempt >= 2 {
			config.CurvePreferences = []tls.CurveID{tls.CurveP256}
		}
	})
	s := p.session(t, nil)
	resumedGet(t, s, p.server.URL)
	assertPSK(t, await(t, p.hellos), false)
	s.transport.CloseIdleConnections()
	if got := resumedGet(t, s, p.server.URL); got.Resumed {
		t.Fatal("HRR fallback must perform a full handshake")
	}
	assertPSK(t, await(t, p.hellos), true)
	assertPSK(t, await(t, p.hellos), false)
	if p.attempts.Load() != 3 {
		t.Fatalf("expected one fallback, got %d attempts", p.attempts.Load())
	}
	s.mu.Lock()
	connections := len(s.connections)
	s.mu.Unlock()
	if connections != 1 {
		t.Fatalf("failed handshake leaked tracked connection: %d", connections)
	}
}

func TestTLSResumptionTLS12Tickets(t *testing.T) {
	p := newResumptionPeer(t, func(config *tls.Config, _ int32) {
		config.MinVersion, config.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	})
	s := p.session(t, func(o *Options) {
		data := strings.Replace(localProfile, `"max_version": 772`, `"max_version": 771`, 1)
		data = strings.Replace(data, `"cipher_suites": [4865, 4866, 4867, 49199, 49200]`, `"cipher_suites": [49199]`, 1)
		data = strings.Replace(data, `"values":[772,771]`, `"values":[771]`, 1)
		data = strings.Replace(data, `{"type":"psk_key_exchange_modes","values":[1]}`, `{"type":"session_ticket"}`, 1)
		var err error
		o.Profile, err = profile.Load([]byte(data))
		if err != nil {
			t.Fatal(err)
		}
	})
	if got := resumedGet(t, s, p.server.URL); got.Resumed {
		t.Fatal("first TLS1.2 handshake resumed")
	}
	cold := assertPSK(t, await(t, p.hellos), false)
	if payload, exists := cold.payloads[35]; !exists || len(payload) != 0 {
		t.Fatal("expected empty initial session_ticket extension")
	}
	s.transport.CloseIdleConnections()
	if got := resumedGet(t, s, p.server.URL); !got.Resumed {
		t.Fatal("TLS1.2 ticket was not used")
	}
	warm := assertPSK(t, await(t, p.hellos), false)
	if len(warm.payloads[35]) == 0 {
		t.Fatal("TLS1.2 resumed ClientHello has no ticket")
	}
	if !reflect.DeepEqual(cold.extensions, warm.extensions) {
		t.Fatal("TLS1.2 resumption changed extension order")
	}
}

func TestTLSResumptionConcurrentNewConnections(t *testing.T) {
	p := newResumptionPeer(t, nil)
	s := p.session(t, nil)
	resumedGet(t, s, p.server.URL)
	assertPSK(t, await(t, p.hellos), false)
	const count = 16
	var wg sync.WaitGroup
	ctx := testContext(t)
	for range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := s.dialTLS(ctx, "tcp", p.server.Listener.Addr().String(), nil)
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			if !conn.(*utls.UConn).ConnectionState().DidResume {
				t.Error("concurrent TLS connection did not resume")
			}
		}()
	}
	wg.Wait()
	for range count {
		assertPSK(t, await(t, p.hellos), true)
	}
}

func TestTLSResumptionDoesNotRetryCertificateFailure(t *testing.T) {
	p := newResumptionPeer(t, nil)
	s := p.session(t, func(o *Options) { o.RootCAs = x509.NewCertPool() })
	if _, err := s.Do(testContext(t), Request{Method: "GET", URL: p.server.URL}); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	if p.attempts.Load() != 1 {
		t.Fatalf("certificate failure was retried: %d attempts", p.attempts.Load())
	}
}

func TestSessionTicketCacheConcurrentCloseAndScope(t *testing.T) {
	cache := &sessionTicketCache{cache: utls.NewLRUClientSessionCache(64)}
	var wg sync.WaitGroup
	ready := make(chan struct{}, 64)
	startClose := make(chan struct{})
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			view := authoritySessionCache{cache: cache, authority: string(rune(i)) + ":443"}
			state := new(utls.ClientSessionState)
			view.Put("same-server", state)
			if got, ok := view.Get("same-server"); !ok || got != state {
				t.Error("initial cache write lost or crossed authority")
			}
			ready <- struct{}{}
			<-startClose
			for range 50 {
				view.Put("same-server", state)
				if got, ok := view.Get("same-server"); ok && got != state {
					t.Error("cross-authority cache entry")
				}
				view.Put("same-server", nil)
			}
		}()
	}
	for range 64 {
		<-ready
	}
	close(startClose)
	cache.close()
	wg.Wait()
	cache.Put("after-close", new(utls.ClientSessionState))
	if _, ok := cache.Get("after-close"); ok {
		t.Fatal("closed cache was repopulated")
	}
}
