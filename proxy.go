package requestsutls

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func parseProxy(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		// url.Error includes its input, which may contain proxy credentials.
		return nil, errors.New("requests-utls: invalid proxy URL")
	}
	if u.Scheme != "http" || u.Opaque != "" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return nil, errors.New("requests-utls: proxy must be an absolute http URL without path, query, or fragment")
	}
	host := u.Hostname()
	if host == "" || strings.TrimSpace(host) != host || (strings.Contains(host, ":") && !strings.HasPrefix(u.Host, "[")) || strings.HasSuffix(u.Host, ":") {
		return nil, errors.New("requests-utls: invalid proxy host")
	}
	port := u.Port()
	if port == "" {
		port = "80"
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return nil, errors.New("requests-utls: proxy port must be 1..65535")
	}
	u.Host = net.JoinHostPort(host, strconv.FormatUint(n, 10))
	return u, nil
}

type bufferedProxyConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedProxyConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func dialHTTPConnect(ctx context.Context, network, addr string, proxyURL *url.URL) (net.Conn, error) {
	return dialHTTPConnectTimeouts(ctx, network, addr, proxyURL, 0, 0)
}
func dialHTTPConnectTimeouts(ctx context.Context, network, addr string, proxyURL *url.URL, connectTimeout, proxyTimeout time.Duration) (result net.Conn, resultErr error) {
	start := time.Now()

	if ctx == nil || proxyURL == nil {
		return nil, errors.New("requests-utls: proxy CONNECT requires a context and proxy URL")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" || strings.ContainsAny(addr, "\r\n\t ") {
		return nil, errors.New("requests-utls: invalid proxy CONNECT destination")
	}
	dialCtx, dialCancel := phaseContext(ctx, connectTimeout)
	conn, err := (&net.Dialer{}).DialContext(dialCtx, network, proxyURL.Host)
	if err != nil {
		err = stageError(dialCtx, "connect", start, err)
	}
	dialCancel()
	if err != nil {
		return nil, fmt.Errorf("requests-utls: proxy dial: %w", err)
	}
	start = time.Now()
	proxyCtx, proxyCancel := phaseContext(ctx, proxyTimeout)
	defer proxyCancel()
	defer func() { resultErr = stageError(proxyCtx, "proxy_connect", start, resultErr) }()
	ctx = proxyCtx
	complete := false
	cancelDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		conn.Close()
		close(cancelDone)
	})
	stopped := false
	stopCancellation := func() {
		if !stopped {
			stopped = true
			if !stop() {
				<-cancelDone
			}
		}
	}
	defer func() {
		stopCancellation()
		if !complete {
			conn.Close()
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("requests-utls: proxy CONNECT deadline: %w", err)
		}
	}
	request := &http.Request{
		Method: http.MethodConnect, URL: &url.URL{Opaque: addr}, Host: addr,
		Header: make(http.Header),
	}
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		credentials := proxyURL.User.Username() + ":" + password
		request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credentials)))
	}
	if err := request.Write(conn); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("requests-utls: proxy CONNECT: %w", ctx.Err())
		}
		return nil, fmt.Errorf("requests-utls: proxy CONNECT write: %w", err)
	}
	// Bound response headers without imposing a limit on the subsequent tunnel.
	reader := bufio.NewReader(io.LimitReader(conn, 64<<10))
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("requests-utls: proxy CONNECT: %w", ctx.Err())
		}
		// A proxy may reflect credentials in a malformed status line. Never
		// include its raw response or the credential-bearing URL in errors.
		return nil, proxyResponseError(err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("requests-utls: proxy CONNECT returned HTTP status %d", response.StatusCode)
	}
	stopCancellation()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("requests-utls: proxy CONNECT: %w", ctx.Err())
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("requests-utls: proxy CONNECT clear deadline: %w", err)
	}
	// ReadResponse can read past the blank line. Keep those bytes before
	// switching away from the header-limited reader to the raw connection.
	buffered := make([]byte, reader.Buffered())
	if _, err := io.ReadFull(reader, buffered); err != nil {
		return nil, errors.New("requests-utls: proxy CONNECT could not preserve buffered tunnel bytes")
	}
	complete = true
	return &bufferedProxyConn{Conn: conn, reader: io.MultiReader(bytes.NewReader(buffered), conn)}, nil
}

// proxyResponseError preserves timeout classification without reflecting proxy
// response text, which may contain credentials, into the caller's error.
func proxyResponseError(err error) error {
	if errors.Is(normalizeTimeout(err), context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return errors.New("requests-utls: proxy CONNECT received an invalid or oversized HTTP response")
}
