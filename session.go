// Package requestsutls provides a concurrent, profile-driven HTTP/2 client.
// This Go prototype deliberately has no mutable default headers or cookie jar.
package requestsutls

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2/hpack"

	h2 "requests-utls/internal/h2"
	"requests-utls/profile"
)

var (
	ErrSessionClosed    = errors.New("requests-utls: session closed")
	ErrQueueFull        = errors.New("requests-utls: request queue full")
	ErrResponseTooLarge = errors.New("requests-utls: response body exceeds limit")
	ErrInvalidRequest   = errors.New("requests-utls: invalid request")
)

// HeaderField is one field occurrence. Slices retain duplicates and their order.
type HeaderField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Request owns the input for a single operation. Do snapshots its slices;
// callers must not mutate them concurrently with Do taking that snapshot.
type Request struct {
	Method  string        `json:"method"`
	URL     string        `json:"url"`
	Headers []HeaderField `json:"headers"`
	// HeadersOrder contains lowercase regular header names. A name listed once
	// groups all its values; repeated names specify each occurrence's position.
	// For a present name, repeated entries must match its number of values.
	// Absent names are ignored, unlisted fields follow in their original order,
	// and an empty list preserves Headers exactly. Pseudo-header order remains
	// part of the Session profile.
	HeadersOrder []string `json:"headers_order,omitempty"`
	Body         []byte   `json:"body,omitempty"`
}

// Response contains the final response's ordered regular fields and raw body.
// Compression and redirects are intentionally not applied in this prototype.
type Response struct {
	StatusCode int           `json:"status_code"`
	Headers    []HeaderField `json:"headers"`
	Body       []byte        `json:"body"`
	Protocol   string        `json:"protocol"`
}

// Options are snapshotted by NewSession. A Session's transport never changes.
type Options struct {
	Profile               *profile.Profile
	ProxyURL              string     // Explicit http:// CONNECT proxy; empty means direct.
	ProxyAuth             *ProxyAuth // Optional separate Basic credentials; cannot combine with URL userinfo.
	RootCAs               *x509.CertPool
	InsecureSkipVerify    bool
	MaxConcurrentRequests int   // 0 means 64; includes body consumption.
	MaxPendingRequests    int   // 0 means no waiting queue.
	MaxResponseBytes      int64 // 0 means 32 MiB.
	MaxUnprocessedRetries int   // 0 means 3; -1 disables; maximum 32. Only proven-unprocessed requests.
}

// ProxyAuth is snapshotted when the Session is created. Credentials are sent
// only to the proxy in the CONNECT request, never as origin request headers.
type ProxyAuth struct {
	Username string
	Password string
}

// Session is safe for concurrent Do and Close calls. Create another Session to
// change the profile or trust configuration; connections cannot cross Sessions.
type Session struct {
	profile     *profile.Profile
	roots       *x509.CertPool
	insecure    bool
	proxyURL    *url.URL
	transport   *h2.Transport
	maxResponse int64
	slots       chan struct{}
	running     chan struct{}
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	closed      bool
	connections map[*trackedConn]struct{}
	requests    sync.WaitGroup
	closeDone   chan struct{}
}

func NewSession(o Options) (*Session, error) {
	if o.Profile == nil {
		return nil, errors.New("requests-utls: profile is required")
	}
	proxyURL, err := parseProxy(o.ProxyURL)
	if err != nil {
		return nil, err
	}
	if o.ProxyAuth != nil {
		if proxyURL == nil {
			return nil, errors.New("requests-utls: proxy authentication requires ProxyURL")
		}
		if proxyURL.User != nil {
			return nil, errors.New("requests-utls: use either URL credentials or ProxyAuth, not both")
		}
		if strings.Contains(o.ProxyAuth.Username, ":") {
			return nil, errors.New("requests-utls: Basic proxy username cannot contain a colon")
		}
		proxyURL.User = url.UserPassword(o.ProxyAuth.Username, o.ProxyAuth.Password)
	}
	if o.MaxConcurrentRequests < 0 || o.MaxPendingRequests < 0 || o.MaxResponseBytes < 0 {
		return nil, errors.New("requests-utls: limits must be nonnegative")
	}
	if o.MaxUnprocessedRetries < -1 || o.MaxUnprocessedRetries > 32 {
		return nil, errors.New("requests-utls: MaxUnprocessedRetries must be -1..32")
	}
	if o.MaxConcurrentRequests == 0 {
		o.MaxConcurrentRequests = 64
	}
	if o.MaxConcurrentRequests > 1_000_000 || o.MaxPendingRequests > 1_000_000 {
		return nil, errors.New("requests-utls: request limits exceed 1000000")
	}
	if o.MaxResponseBytes == 0 {
		o.MaxResponseBytes = 32 << 20
	}
	if o.MaxResponseBytes == int64(^uint64(0)>>1) {
		return nil, errors.New("requests-utls: response limit must leave room for overflow detection")
	}
	w := o.Profile.HTTP2()
	wp := &h2.WireProfile{ConnectionWindowUpdate: w.ConnectionWindowUpdate, PseudoHeaderOrder: append([]string(nil), w.PseudoHeaderOrder...)}
	for _, setting := range w.Settings {
		wp.Settings = append(wp.Settings, h2.Setting{ID: h2.SettingID(setting.ID), Val: setting.Value})
	}
	if w.HeaderPriority != nil {
		p := w.HeaderPriority
		if p.Weight < 1 || p.Weight > 256 {
			return nil, errors.New("requests-utls: priority weight must be 1..256")
		}
		wp.HeaderPriority = &h2.PriorityParam{StreamDep: p.StreamDep, Exclusive: p.Exclusive, Weight: uint8(p.Weight - 1)}
	}
	if err := wp.Validate(); err != nil {
		return nil, fmt.Errorf("requests-utls: HTTP/2 profile: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{
		profile: o.Profile, proxyURL: proxyURL, insecure: o.InsecureSkipVerify, maxResponse: o.MaxResponseBytes,
		slots:   make(chan struct{}, o.MaxConcurrentRequests+o.MaxPendingRequests),
		running: make(chan struct{}, o.MaxConcurrentRequests),
		ctx:     ctx, cancel: cancel, connections: make(map[*trackedConn]struct{}), closeDone: make(chan struct{}),
	}
	if o.RootCAs != nil {
		s.roots = o.RootCAs.Clone()
	}
	s.transport = &h2.Transport{
		WireProfile:           wp,
		MaxUnprocessedRetries: o.MaxUnprocessedRetries,
		DialTLSContext:        s.dialTLS,
		DisableCompression:    true,
		IdleConnTimeout:       30 * time.Second,
	}
	return s, nil
}

// ProfileHash identifies the immutable configuration used for this Session.
func (s *Session) ProfileHash() string { return s.profile.Hash() }

func (s *Session) Do(ctx context.Context, input Request) (*Response, error) {
	if ctx == nil {
		return nil, errors.New("requests-utls: nil context")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrSessionClosed
	}
	select {
	case s.slots <- struct{}{}:
	default:
		s.mu.Unlock()
		return nil, ErrQueueFull
	}
	s.requests.Add(1) // serialized with Close, so Wait cannot race an Add.
	s.mu.Unlock()
	defer s.requests.Done()
	defer func() { <-s.slots }()

	requestCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	defer cancel()
	if s.ctx.Err() != nil {
		return nil, ErrSessionClosed
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Take ownership before waiting for a running slot.
	input.Headers = append([]HeaderField(nil), input.Headers...)
	input.HeadersOrder = append([]string(nil), input.HeadersOrder...)
	input.Body = bytes.Clone(input.Body)
	req, fields, err := prepareRequest(requestCtx, input)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	select {
	case s.running <- struct{}{}:
		defer func() { <-s.running }()
	case <-requestCtx.Done():
		return nil, s.requestError(ctx, requestCtx.Err())
	}
	if requestCtx.Err() != nil {
		return nil, s.requestError(ctx, requestCtx.Err())
	}

	var raw []hpack.HeaderField
	req = h2.WithOrderedHeaders(req, fields)
	req = h2.WithResponseHeaderSink(req, &raw)
	res, err := s.transport.RoundTrip(req)
	if err != nil {
		return nil, s.requestError(ctx, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, s.maxResponse+1))
	if err != nil {
		return nil, s.requestError(ctx, err)
	}
	if int64(len(body)) > s.maxResponse {
		return nil, ErrResponseTooLarge
	}
	headers := make([]HeaderField, 0, len(raw))
	for _, f := range raw {
		headers = append(headers, HeaderField{Name: f.Name, Value: f.Value})
	}
	return &Response{StatusCode: res.StatusCode, Headers: headers, Body: body, Protocol: res.Proto}, nil
}

func (s *Session) requestError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if s.ctx.Err() != nil {
		return ErrSessionClosed
	}
	return err
}

func prepareRequest(ctx context.Context, in Request) (*http.Request, []hpack.HeaderField, error) {
	headers, err := orderHeaders(in.Headers, in.HeadersOrder)
	if err != nil {
		return nil, nil, err
	}
	if in.Method == "" {
		in.Method = "GET"
	}
	if in.Method == "CONNECT" {
		return nil, nil, errors.New("requests-utls: CONNECT requests are not supported by the prototype")
	}
	req, err := http.NewRequestWithContext(ctx, in.Method, in.URL, bytes.NewReader(in.Body))
	if err != nil {
		return nil, nil, err
	}
	if req.URL.Scheme != "https" || req.URL.Hostname() == "" || req.URL.User != nil || req.URL.Fragment != "" {
		return nil, nil, errors.New("requests-utls: an absolute https URL without userinfo or fragment is required")
	}
	// NewRequest's GetBody can rewind this owned snapshot. The transport may use
	// it only when HTTP/2 proves the peer did not process the request (for example
	// GOAWAY covering a lower last-stream ID). Ambiguous failures are not replayed.
	fields := make([]hpack.HeaderField, 0, len(in.Headers))
	seenLength := false
	for _, f := range headers {
		if !httpguts.ValidHeaderFieldName(f.Name) || strings.ToLower(f.Name) != f.Name || !httpguts.ValidHeaderFieldValue(f.Value) || strings.Trim(f.Value, " \t") != f.Value {
			return nil, nil, fmt.Errorf("requests-utls: invalid HTTP/2 header %q (lowercase regular names required)", f.Name)
		}
		switch f.Name {
		case "host", "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", "trailer":
			return nil, nil, fmt.Errorf("requests-utls: unsupported HTTP/2 header %q", f.Name)
		case "te":
			if f.Value != "trailers" {
				return nil, nil, errors.New("requests-utls: te must be trailers")
			}
		case "content-length":
			n, parseErr := strconv.ParseUint(f.Value, 10, 63)
			if seenLength || parseErr != nil || f.Value == "" || strings.HasPrefix(f.Value, "+") || n != uint64(len(in.Body)) {
				return nil, nil, errors.New("requests-utls: content-length must appear once and match body length")
			}
			seenLength = true
		}
		fields = append(fields, hpack.HeaderField{Name: f.Name, Value: f.Value})
		// Auxiliary semantic view; actual wire encoding consumes fields directly.
		req.Header.Add(f.Name, f.Value)
	}
	return req, fields, nil
}

func (s *Session) dialTLS(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	stop := context.AfterFunc(s.ctx, cancel)
	defer cancel()
	defer stop()
	var conn net.Conn
	var err error
	if s.proxyURL != nil {
		conn, err = dialHTTPConnect(dialCtx, network, addr, s.proxyURL)
	} else {
		conn, err = (&net.Dialer{}).DialContext(dialCtx, network, addr)
	}
	if err != nil {
		return nil, err
	}
	tc := &trackedConn{Conn: conn, session: s}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		conn.Close()
		return nil, ErrSessionClosed
	}
	s.connections[tc] = struct{}{}
	s.mu.Unlock()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		tc.Close()
		return nil, err
	}
	spec, err := s.profile.NewClientHelloSpec()
	if err != nil {
		tc.Close()
		return nil, err
	}
	uconn := utls.UClient(tc, &utls.Config{ServerName: host, RootCAs: s.roots, InsecureSkipVerify: s.insecure, SessionTicketsDisabled: true}, utls.HelloCustom)
	if err = uconn.ApplyPreset(spec); err == nil {
		err = uconn.HandshakeContext(dialCtx)
	}
	if err != nil {
		tc.Close()
		return nil, fmt.Errorf("requests-utls: TLS handshake: %w", err)
	}
	if uconn.ConnectionState().NegotiatedProtocol != "h2" {
		tc.Close()
		return nil, errors.New("requests-utls: server did not negotiate h2; HTTP/1.1 fallback is not implemented")
	}
	return uconn, nil
}

// Close cancels all admitted requests, closes active/idle connections and waits
// for Do calls to release resources. Concurrent/repeated calls are idempotent.
func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		<-s.closeDone
		return nil
	}
	s.closed = true
	s.cancel()
	connections := make([]*trackedConn, 0, len(s.connections))
	for c := range s.connections {
		connections = append(connections, c)
	}
	s.mu.Unlock()
	for _, c := range connections {
		c.Close()
	}
	s.requests.Wait()
	s.transport.CloseIdleConnections()
	close(s.closeDone)
	return nil
}

type trackedConn struct {
	net.Conn
	session  *Session
	once     sync.Once
	closeErr error
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.closeErr = c.Conn.Close()
		c.session.mu.Lock()
		delete(c.session.connections, c)
		c.session.mu.Unlock()
	})
	return c.closeErr
}
