package requestsutls

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http/httpguts"
)

var errProtocolHandoff = errors.New("requests-utls: negotiated HTTP protocol handoff")

// Each HTTP/1 connection has at most one owner. Idle connections and completed
// TLS handshakes waiting for the H2 transport are protected by protocolMu.
type http1Conn struct {
	conn           net.Conn
	reader         *bufio.Reader
	idleTimer      *time.Timer
	poolGeneration uint64
}

func newHTTP1Conn(conn net.Conn) *http1Conn {
	return &http1Conn{conn: conn, reader: bufio.NewReader(conn)}
}

func httpAuthority(req *http.Request) string {
	port := req.URL.Port()
	if port == "" {
		port = "443"
		if req.URL.Scheme == "http" {
			port = "80"
		}
	}
	return net.JoinHostPort(strings.ToLower(req.URL.Hostname()), port)
}

func httpOrigin(req *http.Request) string { return req.URL.Scheme + "://" + httpAuthority(req) }

func (s *Session) setHTTPProtocol(key, protocol string) {
	s.protocolMu.Lock()
	if s.ctx.Err() == nil {
		s.protocols[key] = protocol
	}
	s.protocolMu.Unlock()
}

func (s *Session) httpProtocolKnown(req *http.Request) bool {
	s.protocolMu.Lock()
	defer s.protocolMu.Unlock()
	return s.protocols[httpOrigin(req)] != ""
}

func (s *Session) useHTTP1(req *http.Request) bool {
	if s.forceHTTP1 || req.URL.Scheme == "http" {
		return true
	}
	s.protocolMu.Lock()
	defer s.protocolMu.Unlock()
	if protocol := s.protocols[httpOrigin(req)]; protocol != "" {
		return protocol == "http/1.1"
	}
	return s.profile.HTTPVersion() == "http/1.1"
}

func negotiatedHTTP1(conn net.Conn) bool {
	state := conn.(*utls.UConn).ConnectionState()
	return state.NegotiatedProtocol == "http/1.1" || state.NegotiatedProtocol == ""
}

func (s *Session) discoverHTTPProtocol(ctx context.Context, req *http.Request) error {
	conn, err := s.dialTLSConnection(ctx, "tcp", httpAuthority(req))
	if err != nil {
		return err
	}
	isH1 := negotiatedHTTP1(conn)
	protocol := "h2"
	if isH1 {
		protocol = "http/1.1"
	}
	s.setHTTPProtocol(httpOrigin(req), protocol)
	s.putHTTPConn(httpOrigin(req), newHTTP1Conn(conn), isH1)
	return nil
}

func (s *Session) takeHTTPConn(key string, h1 bool) *http1Conn {
	s.protocolMu.Lock()
	defer s.protocolMu.Unlock()
	pool := s.http2Ready
	if h1 {
		pool = s.http1Idle
	}
	entries := pool[key]
	if len(entries) == 0 {
		return nil
	}
	conn := entries[len(entries)-1]
	conn.poolGeneration++
	pool[key] = entries[:len(entries)-1]
	if len(pool[key]) == 0 {
		delete(pool, key)
	}
	if conn.idleTimer != nil {
		conn.idleTimer.Stop()
		conn.idleTimer = nil
	}
	return conn
}

func (s *Session) putHTTPConn(key string, conn *http1Conn, h1 bool) {
	s.protocolMu.Lock()
	if s.ctx.Err() != nil {
		s.protocolMu.Unlock()
		conn.conn.Close()
		return
	}
	pool := s.http2Ready
	if h1 {
		pool = s.http1Idle
	}
	pool[key] = append(pool[key], conn)
	conn.poolGeneration++
	generation := conn.poolGeneration
	conn.idleTimer = time.AfterFunc(30*time.Second, func() {
		s.protocolMu.Lock()
		if conn.poolGeneration != generation {
			s.protocolMu.Unlock()
			return
		}
		entries := pool[key]
		found := false
		for i, entry := range entries {
			if entry == conn {
				pool[key] = append(entries[:i], entries[i+1:]...)
				if len(pool[key]) == 0 {
					delete(pool, key)
				}
				found = true
				break
			}
		}
		s.protocolMu.Unlock()
		if found {
			conn.conn.Close()
		}
	})
	s.protocolMu.Unlock()
}

func (s *Session) closeHTTPPools() {
	s.protocolMu.Lock()
	var pending []*http1Conn
	for _, pool := range []map[string][]*http1Conn{s.http1Idle, s.http2Ready} {
		for _, entries := range pool {
			for _, conn := range entries {
				if conn.idleTimer != nil {
					conn.idleTimer.Stop()
				}
				pending = append(pending, conn)
			}
		}
		clear(pool)
	}
	clear(s.protocols)
	s.protocolMu.Unlock()
	for _, conn := range pending {
		conn.conn.Close()
	}
}

func prepareHTTP1Request(ctx context.Context, in Request) (*http.Request, []HeaderField, error) {
	if in.Method == "" {
		in.Method = "GET"
	}
	if in.Method == http.MethodConnect {
		return nil, nil, errors.New("CONNECT requests are not supported")
	}
	req, err := http.NewRequestWithContext(ctx, in.Method, in.URL, bytes.NewReader(in.Body))
	if err != nil {
		return nil, nil, err
	}
	if (req.URL.Scheme != "https" && req.URL.Scheme != "http") || req.URL.Hostname() == "" || req.URL.User != nil || req.URL.Fragment != "" || req.URL.Opaque != "" {
		return nil, nil, errors.New("an absolute http or https URL without userinfo or fragment is required")
	}
	if !httpguts.ValidHostHeader(req.URL.Host) || strings.HasSuffix(req.URL.Host, ":") {
		return nil, nil, errors.New("invalid request URL authority")
	}
	if port := req.URL.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return nil, nil, errors.New("request URL port must be 1..65535")
		}
	}
	headers, _, err := normalizeContentLength(in.Headers, len(in.Body))
	if err != nil {
		return nil, nil, err
	}
	seenHost, seenLength := false, false
	for _, field := range headers {
		if !httpguts.ValidHeaderFieldName(field.Name) || !httpguts.ValidHeaderFieldValue(field.Value) || strings.Trim(field.Value, " \t") != field.Value {
			return nil, nil, fmt.Errorf("invalid HTTP header %q", field.Name)
		}
		switch strings.ToLower(field.Name) {
		case "host":
			if seenHost || field.Value == "" || !httpguts.ValidHostHeader(field.Value) {
				return nil, nil, errors.New("Host must appear once and contain a valid authority")
			}
			seenHost = true
			req.Host = field.Value
		case "content-length":
			n, err := strconv.ParseUint(field.Value, 10, 63)
			if seenLength || err != nil || strings.HasPrefix(field.Value, "+") || n != uint64(len(in.Body)) {
				return nil, nil, errors.New("content-length must appear once and match body length")
			}
			seenLength = true
		case "transfer-encoding", "upgrade", "trailer", "proxy-authorization", "proxy-connection":
			return nil, nil, fmt.Errorf("unsupported request header %q", field.Name)
		}
		req.Header.Add(field.Name, field.Value)
	}
	headers, err = orderHTTP1Headers(headers, in.HeadersOrder)
	if err != nil {
		return nil, nil, err
	}
	return req, headers, nil
}

func orderHTTP1Headers(headers []HeaderField, order []string) ([]HeaderField, error) {
	// Reuse the same occurrence/group rules with canonical lookup keys, while
	// keeping the original HeaderField values (and therefore their casing).
	return orderHeadersMatching(headers, order, true)
}

func (s *Session) dialHTTP1(ctx context.Context, req *http.Request) (*http1Conn, error) {
	if req.URL.Scheme == "https" {
		conn, err := s.dialTLSConnection(ctx, "tcp", httpAuthority(req))
		if err != nil {
			return nil, err
		}
		if !negotiatedHTTP1(conn) {
			s.setHTTPProtocol(httpOrigin(req), "h2")
			s.putHTTPConn(httpOrigin(req), newHTTP1Conn(conn), false)
			return nil, errProtocolHandoff
		}
		return newHTTP1Conn(conn), nil
	}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var conn net.Conn
	var err error
	if s.proxyURL != nil {
		// The same explicit authenticated CONNECT path works for plain HTTP;
		// proxy credentials remain outside origin request bytes.
		conn, err = dialHTTPConnect(dialCtx, "tcp", httpAuthority(req), s.proxyURL)
	} else {
		conn, err = (&net.Dialer{}).DialContext(dialCtx, "tcp", httpAuthority(req))
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
	return newHTTP1Conn(tc), nil
}

func (s *Session) roundTripHTTP1(req *http.Request, headers []HeaderField, body []byte, order []string) (*Response, error) {
	// Add protocol-required fields only after selecting H1. They participate
	// in this request's order without affecting H2's absent-name semantics.
	headers = append([]HeaderField(nil), headers...)
	seenHost, seenLength := false, false
	for _, field := range headers {
		switch strings.ToLower(field.Name) {
		case "host":
			seenHost = true
		case "content-length":
			seenLength = true
		}
	}
	if !seenHost {
		headers = append(headers, HeaderField{Name: "Host", Value: req.Host})
	}
	if !seenLength && needsContentLength(req.Method, len(body)) {
		headers = append(headers, HeaderField{Name: "Content-Length", Value: strconv.Itoa(len(body))})
	}
	var err error
	headers, err = orderHTTP1Headers(headers, order)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	key := httpOrigin(req)
	conn := s.takeHTTPConn(key, true)
	if conn == nil {
		var err error
		conn, err = s.dialHTTP1(req.Context(), req)
		if err != nil {
			return nil, err
		}
	}
	reusable := false
	cancelDone := make(chan struct{})
	stop := context.AfterFunc(req.Context(), func() { conn.conn.Close(); close(cancelDone) })
	defer func() {
		if !stop() {
			<-cancelDone
		}
		if req.Context().Err() != nil {
			reusable = false
		}
		if reusable {
			if conn.conn.SetDeadline(time.Time{}) != nil {
				reusable = false
			}
		}
		if reusable {
			s.putHTTPConn(key, conn, true)
		} else {
			conn.conn.Close()
		}
	}()
	if deadline, ok := req.Context().Deadline(); ok {
		if err := conn.conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	fmt.Fprintf(&wire, "%s %s HTTP/1.1\r\n", req.Method, req.URL.RequestURI())
	closeRequest := false
	for _, field := range headers {
		fmt.Fprintf(&wire, "%s: %s\r\n", field.Name, field.Value)
		switch strings.ToLower(field.Name) {
		case "connection":
			closeRequest = closeRequest || httpguts.HeaderValuesContainsToken([]string{field.Value}, "close")
		}
	}
	wire.WriteString("\r\n")
	// No retries after any write attempt: even a partial write may have reached
	// the peer. A stale keep-alive connection therefore fails this request.
	if _, err := io.Copy(conn.conn, &wire); err != nil {
		return nil, fmt.Errorf("HTTP/1.1 request write: %w", err)
	}
	if _, err := io.Copy(conn.conn, bytes.NewReader(body)); err != nil {
		return nil, fmt.Errorf("HTTP/1.1 request body write: %w", err)
	}
	for range 16 {
		head, raw, err := readHTTP1Head(conn.reader)
		if err != nil {
			return nil, fmt.Errorf("HTTP/1.1 response headers: %w", err)
		}
		parsed := bufio.NewReader(io.MultiReader(bytes.NewReader(head), conn.reader))
		res, err := http.ReadResponse(parsed, req)
		if err != nil {
			return nil, fmt.Errorf("HTTP/1.1 response framing: %w", err)
		}
		if res.StatusCode == http.StatusSwitchingProtocols {
			conn.conn.Close()
			res.Body.Close()
			return nil, errors.New("HTTP/1.1 protocol upgrades are not supported")
		}
		if res.StatusCode >= 100 && res.StatusCode < 200 {
			res.Body.Close()
			if parsed.Buffered() != 0 {
				// ReadResponse may prefetch the final response after a 1xx.
				buffered := make([]byte, parsed.Buffered())
				io.ReadFull(parsed, buffered)
				conn.reader = bufio.NewReader(io.MultiReader(bytes.NewReader(buffered), conn.reader))
			}
			continue
		}
		framedBody := &http1BodyEOF{ReadCloser: res.Body}
		res.Body = framedBody
		data, decoded, err := readResponseBody(res, s.maxResponse, !s.disableContentDecoding)
		if err != nil {
			conn.conn.Close()
			res.Body.Close()
			return nil, err
		}
		if !framedBody.eof {
			// A codec can finish before an incomplete HTTP body finishes. Never
			// let Body.Close drain an unbounded or stalled leftover representation.
			conn.conn.Close()
			res.Body.Close()
			return nil, errors.New("HTTP/1.1 content decoder ended before the response body framing")
		}
		if err := res.Body.Close(); err != nil {
			return nil, err
		}
		// Extra bytes without another request are unsolicited and must not become
		// a future response. EOF-delimited and Connection: close bodies aren't pooled.
		reusable = !res.Close && !closeRequest && parsed.Buffered() == 0 && conn.reader.Buffered() == 0
		return &Response{StatusCode: res.StatusCode, Headers: raw, Body: data, Protocol: res.Proto, Decoded: decoded}, nil
	}
	return nil, errors.New("HTTP/1.1 response has too many informational header blocks")
}

type http1BodyEOF struct {
	io.ReadCloser
	eof bool
}

func (body *http1BodyEOF) Read(p []byte) (int, error) {
	n, err := body.ReadCloser.Read(p)
	if err == io.EOF {
		body.eof = true
	}
	return n, err
}

func readHTTP1Head(reader *bufio.Reader) ([]byte, []HeaderField, error) {
	const maximum = 64 << 10
	var head bytes.Buffer
	var fields []HeaderField
	hasLength, hasTransferEncoding := false, false
	for lineNumber := 0; ; lineNumber++ {
		var line []byte
		for {
			fragment, err := reader.ReadSlice('\n')
			if head.Len()+len(line)+len(fragment) > maximum {
				return nil, nil, errors.New("response headers exceed 64 KiB")
			}
			line = append(line, fragment...)
			if err == bufio.ErrBufferFull {
				continue
			}
			if err != nil {
				return nil, nil, err
			}
			break
		}
		if !bytes.HasSuffix(line, []byte("\r\n")) {
			return nil, nil, errors.New("response header lines require CRLF")
		}
		head.Write(line)
		text := string(line[:len(line)-2])
		if lineNumber == 0 {
			if !strings.HasPrefix(text, "HTTP/1.1 ") && !strings.HasPrefix(text, "HTTP/1.0 ") {
				return nil, nil, errors.New("invalid HTTP/1.x status line")
			}
			continue
		}
		if text == "" {
			return head.Bytes(), fields, nil
		}
		name, value, found := strings.Cut(text, ":")
		if !found || !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return nil, nil, errors.New("invalid HTTP/1.1 response header")
		}
		switch strings.ToLower(name) {
		case "content-length":
			hasLength = true
		case "transfer-encoding":
			hasTransferEncoding = true
		}
		if hasLength && hasTransferEncoding {
			return nil, nil, errors.New("ambiguous HTTP/1.1 response framing: both Content-Length and Transfer-Encoding")
		}
		fields = append(fields, HeaderField{Name: name, Value: strings.Trim(value, " \t")})
	}
}
