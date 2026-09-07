// requests-utls-testpeer is a loopback-only HTTP/2 peer for external bindings'
// integration tests. Stdout contains exactly one JSON startup descriptor.
package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/chuu3/requests-utls/internal/testserver"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/net/http2/hpack"
)

type barrier struct {
	size    int
	arrived int
	ready   chan struct{}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var barriersMu sync.Mutex
	barriers := make(map[string]*barrier)
	var activeDelays atomic.Int64
	peer, err := testserver.New(func(ctx context.Context, request testserver.Request) testserver.Response {
		path, err := url.Parse(request.Header(":path"))
		if err != nil {
			return testserver.Response{Status: "400"}
		}
		switch path.Path {
		case "/stats":
			barriersMu.Lock()
			arrivals := make(map[string]int, len(barriers))
			for group, b := range barriers {
				arrivals[group] = b.arrived
			}
			barriersMu.Unlock()
			body, _ := json.Marshal(map[string]any{"active_delays": activeDelays.Load(), "barriers": arrivals})
			return testserver.Response{Body: body}
		case "/delay":
			ms, _ := strconv.Atoi(path.Query().Get("ms"))
			if ms <= 0 || ms > 30_000 {
				return testserver.Response{Status: "400"}
			}
			activeDelays.Add(1)
			defer activeDelays.Add(-1)
			timer := time.NewTimer(time.Duration(ms) * time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				return testserver.Response{}
			}
		case "/barrier":
			size, _ := strconv.Atoi(path.Query().Get("size"))
			group := path.Query().Get("group")
			if group == "" || size < 1 || size > 128 {
				return testserver.Response{Status: "400"}
			}
			barriersMu.Lock()
			b := barriers[group]
			if b == nil {
				b = &barrier{size: size, ready: make(chan struct{})}
				barriers[group] = b
			}
			if b.size != size || b.arrived >= b.size {
				barriersMu.Unlock()
				return testserver.Response{Status: "400"}
			}
			b.arrived++
			if b.arrived == b.size {
				close(b.ready)
			}
			barriersMu.Unlock()
			select {
			case <-b.ready:
			case <-ctx.Done():
				return testserver.Response{}
			}
		}
		headers := make([][2]string, 0, len(request.Headers))
		for _, field := range request.Headers {
			if !strings.HasPrefix(field.Name, ":") {
				headers = append(headers, [2]string{field.Name, field.Value})
			}
		}
		body, _ := json.Marshal(struct {
			Headers    [][2]string `json:"headers"`
			Authority  string      `json:"authority"`
			BodyBase64 string      `json:"body_base64"`
			Connection int         `json:"connection"`
			StreamID   uint32      `json:"stream_id"`
			DidResume  bool        `json:"tls_did_resume"`
		}{
			Headers: headers, Authority: request.Header(":authority"), BodyBase64: base64.StdEncoding.EncodeToString(request.Body),
			Connection: request.Connection, StreamID: request.StreamID, DidResume: request.DidResume,
		})
		response := testserver.Response{Body: body, GoAway: path.Path == "/reconnect", Headers: []hpack.HeaderField{
			{Name: "content-type", Value: "application/json"},
			{Name: "set-cookie", Value: "peer_first=one; Path=/"},
			{Name: "x-peer", Value: "between"},
			{Name: "set-cookie", Value: "peer_second=two; Path=/"},
		}}
		if strings.HasPrefix(path.Path, "/compressed/") {
			coding := strings.TrimPrefix(path.Path, "/compressed/")
			if size, _ := strconv.Atoi(path.Query().Get("size")); size > 0 && size <= 1<<20 {
				body = bytes.Repeat([]byte("x"), size)
			}
			response.Body, err = compressBody(body, coding)
			if err != nil {
				return testserver.Response{Status: "400"}
			}
			if path.Query().Get("corrupt") == "1" {
				response.Body = []byte("invalid compressed data")
			}
			if coding == "raw-deflate" {
				coding = "deflate"
			}
			response.Headers = append(response.Headers, hpack.HeaderField{Name: "content-encoding", Value: coding})
		}
		return response
	})
	if err != nil {
		return err
	}
	defer peer.Close()
	peerURL, _ := url.Parse(peer.URL)
	proxyURL, closeProxy, err := startProxy(peerURL.Host)
	if err != nil {
		return err
	}
	defer closeProxy()
	h1 := startHTTP1Peer()
	defer h1.Close()
	h1URL, _ := url.Parse(h1.URL)
	h1Proxy, closeH1Proxy, err := startProxy(h1URL.Host)
	if err != nil {
		return err
	}
	defer closeH1Proxy()
	descriptor := map[string]string{
		"url":             peer.URL,
		"ca_pem":          string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: peer.Certificate.Raw})),
		"proxy_url":       proxyURL,
		"proxy_username":  "integration-user",
		"proxy_password":  "integration-password",
		"http1_url":       h1.URL,
		"http1_ca_pem":    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h1.Certificate().Raw})),
		"http1_proxy_url": h1Proxy,
	}
	if err := json.NewEncoder(os.Stdout).Encode(descriptor); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	return nil
}

func compressBody(body []byte, coding string) ([]byte, error) {
	for _, layer := range strings.Split(coding, ",") {
		var output bytes.Buffer
		var writer io.WriteCloser
		switch strings.TrimSpace(layer) {
		case "gzip":
			writer = gzip.NewWriter(&output)
		case "deflate":
			writer = zlib.NewWriter(&output)
		case "raw-deflate":
			writer, _ = flate.NewWriter(&output, flate.DefaultCompression)
		case "br":
			writer = brotli.NewWriter(&output)
		case "zstd":
			writer, _ = zstd.NewWriter(&output, zstd.WithEncoderConcurrency(1))
		default:
			return nil, fmt.Errorf("unsupported test encoding")
		}
		if _, err := writer.Write(body); err != nil {
			writer.Close()
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		body = output.Bytes()
	}
	return body, nil
}

type connectionKey struct{}

func startHTTP1Peer() *httptest.Server {
	var nextConnection atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read failed", 400)
			return
		}
		response, _ := json.Marshal(map[string]any{"headers": r.Header, "body_base64": base64.StdEncoding.EncodeToString(body),
			"host": r.Host, "connection": r.Context().Value(connectionKey{}), "protocol": r.Proto, "tls_did_resume": r.TLS.DidResume})
		w.Header().Add("Set-Cookie", "peer_first=one; Path=/; HttpOnly")
		w.Header().Add("Set-Cookie", "peer_second=two; Path=/; SameSite=Lax")
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/compressed/") {
			coding := strings.TrimPrefix(r.URL.Path, "/compressed/")
			if size, _ := strconv.Atoi(r.URL.Query().Get("size")); size > 0 && size <= 1<<20 {
				response = bytes.Repeat([]byte("x"), size)
			}
			response, err = compressBody(response, coding)
			if err != nil {
				http.Error(w, "invalid encoding", 400)
				return
			}
			if r.URL.Query().Get("corrupt") == "1" {
				response = []byte("invalid compressed data")
			}
			if coding == "raw-deflate" {
				coding = "deflate"
			}
			w.Header().Set("Content-Encoding", coding)
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(response)))
		if r.URL.Path == "/reconnect" {
			w.Header().Set("Connection", "close")
		}
		w.Write(response)
	}))
	server.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, connectionKey{}, nextConnection.Add(1))
	}
	server.StartTLS()
	return server
}

func startProxy(target string) (string, func(), error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	var mu sync.Mutex
	tunnels := make(map[net.Conn]struct{})
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("integration-user:integration-password"))
		if request.Header.Get("Proxy-Authorization") != want {
			w.Header().Set("Proxy-Authenticate", `Basic realm="integration"`)
			http.Error(w, "authentication required", http.StatusProxyAuthRequired)
			return
		}
		if request.Method != http.MethodConnect || request.Host != target {
			http.Error(w, "target forbidden", http.StatusForbidden)
			return
		}
		upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		client, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		mu.Lock()
		tunnels[client] = struct{}{}
		tunnels[upstream] = struct{}{}
		mu.Unlock()
		defer func() {
			client.Close()
			upstream.Close()
			mu.Lock()
			delete(tunnels, client)
			delete(tunnels, upstream)
			mu.Unlock()
		}()
		if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err := buffered.Flush(); err != nil {
			return
		}
		done := make(chan struct{})
		go func() {
			io.Copy(upstream, buffered)
			upstream.Close()
			close(done)
		}()
		io.Copy(client, upstream)
		client.Close()
		<-done
	})
	go server.Serve(listener)
	return "http://" + listener.Addr().String(), func() {
		server.Close()
		mu.Lock()
		defer mu.Unlock()
		for conn := range tunnels {
			conn.Close()
		}
	}, nil
}
