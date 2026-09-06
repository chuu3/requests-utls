package requestsutls

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chuu3/requests-utls/internal/testserver"
)

func localProxy(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var connections sync.Map
	var workers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Store(conn, true)
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer connections.Delete(conn)
				defer conn.Close()
				handler(conn)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-acceptDone
		connections.Range(func(key, value any) bool {
			key.(net.Conn).Close()
			return true
		})
		workers.Wait()
	})
	return "http://" + listener.Addr().String()
}

func TestParseProxy(t *testing.T) {
	for _, test := range []struct{ input, host string }{
		{"http://proxy.example", "proxy.example:80"},
		{"http://127.0.0.1:8080", "127.0.0.1:8080"},
		{"http://[::1]", "[::1]:80"},
		{"http://user:secret@proxy.example:8080", "proxy.example:8080"},
	} {
		got, err := parseProxy(test.input)
		if err != nil || got == nil || got.Host != test.host {
			t.Errorf("parseProxy valid input: host=%v err=%v", got, err)
		}
	}
	if got, err := parseProxy(""); got != nil || err != nil {
		t.Fatalf("empty proxy should disable proxying: %v %v", got, err)
	}
	for _, raw := range []string{
		"proxy.example:80", "//proxy.example:80", "https://proxy.example", "socks5://proxy.example:1080",
		"http:///", "http://proxy.example/", "http://proxy.example/path", "http://proxy.example?", "http://proxy.example#",
		"http://proxy.example:0", "http://proxy.example:65536", "http://proxy.example:", "http://proxy.example:abc",
		"http://secret:password@proxy.example/%invalid", "http://secret:password@proxy.example?key=value",
		"http://secret:password@proxy.example\n",
	} {
		if _, err := parseProxy(raw); err == nil {
			t.Errorf("accepted malformed proxy URL")
		} else if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "password") {
			t.Errorf("proxy URL error leaked credentials: %v", err)
		}
	}
}

func TestSessionHTTPConnectProxyKeepsAuthenticationOutOfOrigin(t *testing.T) {
	for _, mode := range []string{"url", "separate"} {
		t.Run(mode, func(t *testing.T) {
			server := testServer(t, func(ctx context.Context, request testserver.Request) testserver.Response {
				return testserver.Response{Body: []byte(request.Header("x-marker") + "|" + request.Header("proxy-authorization"))}
			})
			connects := make(chan *http.Request, 4)
			proxyURL := localProxy(t, func(client net.Conn) {
				reader := bufio.NewReader(client)
				request, err := http.ReadRequest(reader)
				if err != nil {
					return
				}
				connects <- request
				upstream, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", request.Host)
				if err != nil {
					fmt.Fprint(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
					return
				}
				defer upstream.Close()
				if _, err := fmt.Fprint(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
					return
				}
				copyDone := make(chan struct{})
				go func() {
					io.Copy(client, upstream)
					client.Close()
					close(copyDone)
				}()
				io.Copy(upstream, reader)
				upstream.Close()
				<-copyDone
			})
			u, err := url.Parse(proxyURL)
			if err != nil {
				t.Fatal(err)
			}
			// A proxy username is opaque, including characters that need URL escaping.
			username, password := "+/8=", "p@ss:word"
			u.User = url.UserPassword(username, password)
			auth := &ProxyAuth{Username: username, Password: password}
			session := testSession(t, server, func(options *Options) {
				if mode == "url" {
					options.ProxyURL = u.String()
				} else {
					options.ProxyURL, options.ProxyAuth = proxyURL, auth
				}
			})
			// Credentials must be snapshotted, not reread from caller-owned state.
			auth.Username, auth.Password = "changed", "changed"
			for i := range 2 {
				marker := fmt.Sprintf("request-%d", i)
				response, err := session.Do(testContext(t), Request{Method: "GET", URL: server.URL + "/via-proxy", Headers: []HeaderField{{Name: "x-marker", Value: marker}}})
				if err != nil || string(response.Body) != marker+"|" {
					t.Fatalf("proxied request: response=%+v err=%v", response, err)
				}
			}
			request := await(t, connects)
			origin, _ := url.Parse(server.URL)
			wantAuthorization := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
			if request.Method != "CONNECT" || request.Host != origin.Host || request.RequestURI != origin.Host || request.Header.Get("Proxy-Authorization") != wantAuthorization {
				t.Fatal("proxy did not receive the expected CONNECT destination and authentication")
			}
			if len(connects) != 0 || server.Snapshot().Connections != 1 {
				t.Fatal("Session failed to reuse the established HTTP/2 proxy tunnel")
			}
		})
	}
}

func TestNewSessionRejectsAmbiguousProxyAuthentication(t *testing.T) {
	for _, options := range []Options{
		{ProxyAuth: &ProxyAuth{Username: "user", Password: "secret"}},
		{ProxyURL: "http://first:secret@localhost:8080", ProxyAuth: &ProxyAuth{Username: "second", Password: "secret"}},
		{ProxyURL: "http://localhost:8080", ProxyAuth: &ProxyAuth{Username: "ambiguous:user", Password: "secret"}},
	} {
		options.Profile = testProfile(t)
		session, err := NewSession(options)
		if err == nil {
			session.Close()
			t.Fatal("accepted missing proxy, conflicting credentials, or colon in Basic username")
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatalf("proxy authentication validation leaked password: %v", err)
		}
	}
}

func TestHTTPConnectPreservesBufferedBytesAndDetachesDialCancellation(t *testing.T) {
	proxyURL := localProxy(t, func(conn net.Conn) {
		if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
			return
		}
		fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\nearly")
		io.Copy(conn, conn)
	})
	p, err := parseProxy(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialHTTPConnect(ctx, "tcp", "origin.example:443", p)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("later")); err != nil {
		t.Fatalf("dial context cancellation closed established tunnel: %v", err)
	}
	got := make([]byte, 10)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "earlylater" {
		t.Fatalf("tunnel lost buffered bytes: got %q err=%v", got, err)
	}
}

func TestHTTPConnectRejectsResponseAndClosesSocket(t *testing.T) {
	for _, response := range []string{
		"HTTP/1.1 407 secret-password-reflected\r\nContent-Length: 999999\r\n\r\n",
		"HTTP/1.1 secret-password-reflected\r\n\r\n",
		"HTTP/1.1 200 OK\r\nX-Large: " + strings.Repeat("x", 70<<10) + "\r\n\r\n",
	} {
		t.Run(fmt.Sprintf("response-length-%d", len(response)), func(t *testing.T) {
			closed := make(chan error, 1)
			proxyURL := localProxy(t, func(conn net.Conn) {
				reader := bufio.NewReader(conn)
				if _, err := http.ReadRequest(reader); err != nil {
					closed <- err
					return
				}
				fmt.Fprint(conn, response)
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, err := reader.ReadByte()
				closed <- err
			})
			p, err := parseProxy(proxyURL)
			if err != nil {
				t.Fatal(err)
			}
			p.User = url.UserPassword("secret", "password")
			conn, err := dialHTTPConnect(testContext(t), "tcp", "origin.example:443", p)
			if err == nil {
				conn.Close()
				t.Fatal("accepted failed, malformed, or oversized CONNECT response")
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "password") {
				t.Fatalf("CONNECT error leaked reflected credentials: %v", err)
			}
			if err := await(t, closed); err == nil {
				t.Fatal("failed CONNECT left a usable socket")
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatalf("failed CONNECT did not close socket: %v", err)
			}
		})
	}
}

func TestHTTPConnectCancellationInterruptsWaitingProxy(t *testing.T) {
	started := make(chan struct{}, 1)
	closed := make(chan error, 1)
	proxyURL := localProxy(t, func(conn net.Conn) {
		reader := bufio.NewReader(conn)
		if _, err := http.ReadRequest(reader); err != nil {
			closed <- err
			return
		}
		started <- struct{}{}
		_, err := reader.ReadByte()
		closed <- err
	})
	p, err := parseProxy(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(testContext(t))
	defer cancel()
	result := make(chan error, 1)
	go func() {
		conn, err := dialHTTPConnect(ctx, "tcp", "origin.example:443", p)
		if conn != nil {
			conn.Close()
		}
		result <- err
	}()
	await(t, started)
	cancel()
	if err := await(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("CONNECT cancellation: %v", err)
	}
	if err := await(t, closed); err == nil {
		t.Fatal("canceled CONNECT did not close proxy socket")
	}
}
