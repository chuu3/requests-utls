// Package requestsutls provides a concurrent, profile-driven HTTP client.
// This Go prototype deliberately has no mutable default headers or cookie jar.
package requestsutls

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
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

	h2 "github.com/chuu3/requests-utls/internal/h2"
	"github.com/chuu3/requests-utls/profile"
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
	// HeadersOrder matches regular header names case-insensitively. A name listed once
	// groups all its values; repeated names specify each occurrence's position.
	// For a present name, repeated entries must match its number of values.
	// Absent names are ignored, unlisted fields follow in their original order,
	// and an empty list preserves field order. Generated fields also participate.
	// Content-Length is calculated from Body. HTTP/1 retains field casing;
	// HTTP/2 lowercases wire names. Pseudo-header order is part of the profile.
	HeadersOrder []string `json:"headers_order,omitempty"`
	Body         []byte   `json:"body,omitempty"`
}

// Response contains the final response's ordered regular fields and body.
// Content decoding is enabled by default; Decoded identifies transformed bodies
// while Headers always retain their original wire values. Redirects are not followed.
type Response struct {
	StatusCode int           `json:"status_code"`
	Headers    []HeaderField `json:"headers"`
	Body       []byte        `json:"body"`
	Protocol   string        `json:"protocol"`
	Decoded    bool          `json:"decoded"`
}

// Options are snapshotted by NewSession. A Session's transport never changes.
type Options struct {
	// Connect/TLS/Proxy timeouts default to 10s when zero. Header/body zero disables
	// the phase limit. The caller context always bounds the whole operation.
	ConnectTimeout           time.Duration
	ProxyConnectTimeout      time.Duration
	TLSHandshakeTimeout      time.Duration
	ResponseHeaderTimeout    time.Duration
	BodyTimeout              time.Duration
	Profile                  *profile.Profile
	ProxyURL                 string     // Explicit http:// CONNECT proxy; empty means direct.
	ProxyAuth                *ProxyAuth // Optional separate Basic credentials; cannot combine with URL userinfo.
	RootCAs                  *x509.CertPool
	InsecureSkipVerify       bool
	DisableSessionResumption bool  // Default false: cache TLS tickets within this Session.
	ForceHTTP1               bool  // Advertise only HTTP/1.1 and use its ordered wire transport.
	RandomJA3                bool  // Shuffle eligible TLS extensions for each new connection.
	DisableContentDecoding   bool  // Return the compressed response bytes unchanged.
	MaxConcurrentRequests    int   // 0 means 64; includes body consumption.
	MaxPendingRequests       int   // 0 means no waiting queue.
	MaxResponseBytes         int64 // 0 means 32 MiB.
	MaxUnprocessedRetries    int   // 0 means 3; -1 disables; maximum 32. Only proven-unprocessed requests.
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
	connectTimeout         time.Duration
	proxyConnectTimeout    time.Duration
	tlsHandshakeTimeout    time.Duration
	responseHeaderTimeout  time.Duration
	bodyTimeout            time.Duration
	profile                *profile.Profile
	roots                  *x509.CertPool
	insecure               bool
	proxyURL               *url.URL
	transport              *h2.Transport
	maxResponse            int64
	sessionCache           *sessionTicketCache
	slots                  chan struct{}
	running                chan struct{}
	ctx                    context.Context
	cancel                 context.CancelFunc
	mu                     sync.Mutex
	closed                 bool
	connections            map[*trackedConn]struct{}
	requests               sync.WaitGroup
	closeDone              chan struct{}
	forceHTTP1             bool
	randomJA3              bool
	disableContentDecoding bool
	protocolMu             sync.Mutex
	protocols              map[string]string
	http1Idle              map[string][]*http1Conn
	http2Ready             map[string][]*http1Conn
}

func NewSession(o Options) (*Session, error) {
	for _, d := range []time.Duration{o.ConnectTimeout, o.ProxyConnectTimeout, o.TLSHandshakeTimeout, o.ResponseHeaderTimeout, o.BodyTimeout} {
		if d < 0 {
			return nil, errors.New("requests-utls: phase timeouts must be nonnegative")
		}
	}
	if o.ConnectTimeout == 0 {
		o.ConnectTimeout = 10 * time.Second
	}
	if o.ProxyConnectTimeout == 0 {
		o.ProxyConnectTimeout = 10 * time.Second
	}
	if o.TLSHandshakeTimeout == 0 {
		o.TLSHandshakeTimeout = 10 * time.Second
	}
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
	if o.Profile.HTTPVersion() == "http/1.1" && len(w.Settings) == 0 {
		// H1 captures do not supply H2 settings. This is distinct from a real
		// H2 capture whose explicitly empty SETTINGS frame must stay empty.
		wp = nil
	}
	if err := wp.Validate(); err != nil {
		if o.Profile.HTTPVersion() != "http/1.1" {
			return nil, fmt.Errorf("requests-utls: HTTP/2 profile: %w", err)
		}
		// An H1 capture has no H2 settings to reproduce. If a future peer
		// negotiates H2 with its original ALPN, use the transport defaults.
		wp = nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{
		connectTimeout: o.ConnectTimeout, proxyConnectTimeout: o.ProxyConnectTimeout,
		tlsHandshakeTimeout: o.TLSHandshakeTimeout, responseHeaderTimeout: o.ResponseHeaderTimeout,
		bodyTimeout: o.BodyTimeout,
		profile:     o.Profile, proxyURL: proxyURL, insecure: o.InsecureSkipVerify, maxResponse: o.MaxResponseBytes,
		slots:   make(chan struct{}, o.MaxConcurrentRequests+o.MaxPendingRequests),
		running: make(chan struct{}, o.MaxConcurrentRequests),
		ctx:     ctx, cancel: cancel, connections: make(map[*trackedConn]struct{}), closeDone: make(chan struct{}),
		forceHTTP1: o.ForceHTTP1, randomJA3: o.RandomJA3,
		disableContentDecoding: o.DisableContentDecoding,
		protocols:              make(map[string]string), http1Idle: make(map[string][]*http1Conn), http2Ready: make(map[string][]*http1Conn),
	}
	if o.RootCAs != nil {
		s.roots = o.RootCAs.Clone()
	}
	if !o.DisableSessionResumption {
		s.sessionCache = &sessionTicketCache{cache: utls.NewLRUClientSessionCache(64)}
	}
	s.transport = &h2.Transport{
		WireProfile:           wp,
		ResponseHeaderTimeout: o.ResponseHeaderTimeout,
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

	queueStart := time.Now()
	// Take ownership before waiting for a running slot.
	input.Headers = append([]HeaderField(nil), input.Headers...)
	input.HeadersOrder = append([]string(nil), input.HeadersOrder...)
	input.Body = bytes.Clone(input.Body)
	req, prepared, err := prepareBaseRequest(requestCtx, input)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	select {
	case s.running <- struct{}{}:
		defer func() { <-s.running }()
	case <-requestCtx.Done():
		return nil, s.requestError(ctx, stageError(requestCtx, "queue", queueStart, requestCtx.Err()))
	}
	if requestCtx.Err() != nil {
		return nil, s.requestError(ctx, requestCtx.Err())
	}

	// Protocol handoffs happen before any HTTP bytes are written. A connection
	// is transferred intact, including its TLS state, without another handshake.
	for range 4 {
		if s.useHTTP1(req) {
			response, err := s.roundTripHTTP1(req, prepared, input.Body, input.HeadersOrder)
			if errors.Is(err, errProtocolHandoff) {
				continue
			}
			if err != nil {
				return nil, s.requestError(ctx, err)
			}
			return response, nil
		}
		// HTTP/2 names are lowercase on wire; HTTP/1 keeps the original casing.
		h2Input := input
		h2Input.Headers = make([]HeaderField, len(input.Headers))
		h2Input.HeadersOrder = append([]string(nil), input.HeadersOrder...)
		for i, name := range h2Input.HeadersOrder {
			h2Input.HeadersOrder[i] = strings.ToLower(name)
		}
		for i, field := range input.Headers {
			h2Input.Headers[i] = HeaderField{Name: strings.ToLower(field.Name), Value: field.Value}
		}
		h2Req, fields, err := prepareRequest(requestCtx, h2Input)
		if err != nil {
			// Filtering can change occurrence counts, or H1 may accept a field
			// rejected by H2. Learn ALPN before rejecting on H2's behalf.
			if !s.httpProtocolKnown(req) {
				if discoverErr := s.discoverHTTPProtocol(requestCtx, req); discoverErr != nil {
					return nil, s.requestError(ctx, discoverErr)
				}
				if s.useHTTP1(req) {
					continue
				}
			}
			return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
		}
		var raw []hpack.HeaderField
		h2Req = h2.WithOrderedHeaders(h2Req, fields)
		h2Req = h2.WithResponseHeaderSink(h2Req, &raw)
		// Body cancellation belongs to this request/stream, never the shared socket.
		h2Ctx, h2Cancel := context.WithCancel(h2Req.Context())
		defer h2Cancel()
		traceCtx, phaseTrace := newH2StageTrace(h2Ctx)
		h2Req = h2Req.WithContext(traceCtx)
		res, err := s.transport.RoundTrip(h2Req)
		if errors.Is(err, errProtocolHandoff) {
			continue
		}
		if err != nil {
			return nil, s.requestError(ctx, phaseTrace.wrap(h2Ctx, err))
		}
		bodyStart := time.Now()
		bodyCtx, bodyCancel := phaseContext(h2Ctx, s.bodyTimeout)
		stopBody := context.AfterFunc(bodyCtx, h2Cancel)
		body, decoded, err := readResponseBody(res, s.maxResponse, !s.disableContentDecoding)
		stopBody()
		if err != nil {
			err = stageError(bodyCtx, "body", bodyStart, err)
		}
		bodyCancel()
		res.Body.Close()
		if err != nil {
			return nil, s.requestError(ctx, err)
		}
		headers := make([]HeaderField, 0, len(raw))
		for _, f := range raw {
			headers = append(headers, HeaderField{Name: f.Name, Value: f.Value})
		}
		return &Response{StatusCode: res.StatusCode, Headers: headers, Body: body, Protocol: res.Proto, Decoded: decoded}, nil
	}
	return nil, errors.New("requests-utls: server repeatedly changed the negotiated HTTP protocol")
}

func (s *Session) requestError(ctx context.Context, err error) error {
	var staged *StageError
	if errors.As(err, &staged) {
		copy := *staged
		copy.Err = s.requestError(ctx, staged.Err)
		return &copy
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if s.ctx.Err() != nil {
		return ErrSessionClosed
	}
	return normalizeTimeout(err)
}

func prepareRequest(ctx context.Context, in Request) (*http.Request, []hpack.HeaderField, error) {
	req, headers, err := prepareBaseRequest(ctx, in)
	if err != nil {
		return nil, nil, err
	}
	if req.URL.Scheme != "https" {
		return nil, nil, errors.New("requests-utls: an absolute https URL is required for HTTP/2")
	}
	headers, omitContentLength, err := normalizeHTTP2Headers(headers)
	if err != nil {
		return nil, nil, err
	}
	seenContentLength := false
	for _, field := range headers {
		seenContentLength = seenContentLength || field.Name == "content-length"
	}
	if !seenContentLength && !omitContentLength && needsContentLength(req.Method, len(in.Body)) {
		headers = append(headers, HeaderField{Name: "content-length", Value: strconv.Itoa(len(in.Body))})
	}
	headers, err = orderHeaders(headers, in.HeadersOrder)
	if err != nil {
		return nil, nil, err
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
		case "trailer":
			return nil, nil, errors.New("requests-utls: request trailers are not supported")
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
	// H2's pool may supply a differently cased DNS authority. H1 handoff,
	// TLS ticket keys, and subsequent requests must use the same origin key.
	if host, port, err := net.SplitHostPort(addr); err == nil {
		addr = net.JoinHostPort(strings.ToLower(host), port)
	}
	key := "https://" + addr
	if ready := s.takeHTTPConn(key, false); ready != nil {
		return ready.conn, nil
	}
	conn, err := s.dialTLSConnection(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if negotiatedHTTP1(conn) {
		s.setHTTPProtocol(key, "http/1.1")
		s.putHTTPConn(key, newHTTP1Conn(conn), true)
		return nil, errProtocolHandoff
	}
	s.setHTTPProtocol(key, "h2")
	return conn, nil
}

func (s *Session) dialTLSConnection(ctx context.Context, network, addr string) (net.Conn, error) {
	dialCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.ctx, cancel)
	defer cancel()
	defer stop()
	conn, retryWithoutTicket, err := s.dialTLSAttempt(dialCtx, network, addr, false)
	if retryWithoutTicket && dialCtx.Err() == nil {
		// This is a failed TLS handshake: no HTTP request has been sent. uTLS
		// cannot rebuild a PSK binder after HelloRetryRequest. Retry exactly
		// once with a full handshake and the original, remaining deadline.
		conn, _, err = s.dialTLSAttempt(dialCtx, network, addr, true)
	}
	return conn, err
}

func (s *Session) dialTLSAttempt(dialCtx context.Context, network, addr string, skipCachedTicket bool) (net.Conn, bool, error) {
	conn, err := s.dialNetwork(dialCtx, network, addr)
	if err != nil {
		return nil, false, err
	}
	tc := &trackedConn{Conn: conn, session: s}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		conn.Close()
		return nil, false, ErrSessionClosed
	}
	s.connections[tc] = struct{}{}
	s.mu.Unlock()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		tc.Close()
		return nil, false, err
	}
	spec, err := s.profile.NewClientHelloSpecWithOptions(profile.ClientHelloOptions{ForceHTTP1: s.forceHTTP1, RandomJA3: s.randomJA3})
	if err != nil {
		tc.Close()
		return nil, false, err
	}
	config := &utls.Config{ServerName: host, RootCAs: s.roots, InsecureSkipVerify: s.insecure, SessionTicketsDisabled: true}
	configureResumption(config, spec, s.sessionCache, addr, skipCachedTicket)
	uconn := utls.UClient(tc, config, utls.HelloCustom)
	tlsStart := time.Now()
	tlsCtx, tlsCancel := phaseContext(dialCtx, s.tlsHandshakeTimeout)
	defer tlsCancel()
	if err = uconn.ApplyPreset(spec); err == nil {
		err = uconn.HandshakeContext(tlsCtx)
	}
	if err != nil {
		tc.Close()
		retry := !skipCachedTicket && config.ClientSessionCache != nil && err.Error() == utlsPSKHelloRetryError
		return nil, retry, stageError(tlsCtx, "tls", tlsStart, err)
	}
	if protocol := uconn.ConnectionState().NegotiatedProtocol; protocol != "h2" && protocol != "http/1.1" && protocol != "" {
		tc.Close()
		return nil, false, errors.New("requests-utls: server negotiated an unsupported ALPN protocol")
	}
	return uconn, false, nil
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
	s.closeHTTPPools()
	if s.sessionCache != nil {
		s.sessionCache.close()
	}
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
