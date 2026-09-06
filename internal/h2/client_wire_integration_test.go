package http2

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
)

func TestSharedDialWaiterHonorsItsOwnCancellation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	tr := &Transport{DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
		close(started)
		select {
		case <-release:
			return nil, errors.New("test dial released")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	first, _ := http.NewRequest("GET", "https://example.com/", nil)
	firstDone := make(chan error, 1)
	go func() { _, err := tr.RoundTrip(first); firstDone <- err }()
	defer func() {
		close(release)
		<-firstDone
		tr.CloseIdleConnections()
	}()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	second := first.Clone(ctx)
	secondDone := make(chan error, 1)
	go func() { _, err := tr.RoundTrip(second); secondDone <- err }()
	select {
	case err := <-secondDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiting request returned %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled request waited for another request's shared dial")
	}
	select {
	case err := <-firstDone:
		firstDone <- err // preserve deferred cleanup
		t.Fatal("canceling a waiter canceled the leading dial")
	default:
	}
}

func TestWireTransportWithStandardHTTP2Server(t *testing.T) {
	payload := bytes.Repeat([]byte("request-data-"), 12000)
	response := bytes.Repeat([]byte("response-data-"), 12000)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || !reflect.DeepEqual(r.Header.Values("X-A"), []string{"1", "3"}) {
			http.Error(w, "invalid HTTP/2 request or duplicate headers", 400)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(body, payload) {
			http.Error(w, "invalid request body", 400)
			return
		}
		w.Header().Add("Set-Cookie", "one=1")
		w.Header().Add("Set-Cookie", "two=2")
		w.Write(response)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	tr := &Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots},
		WireProfile: &WireProfile{
			Settings: []Setting{
				{SettingHeaderTableSize, 65536}, {SettingEnablePush, 0},
				{SettingInitialWindowSize, 6291456}, {SettingMaxHeaderListSize, 262144},
			},
			ConnectionWindowUpdate: 15663105,
			PseudoHeaderOrder:      []string{":method", ":authority", ":scheme", ":path"},
			HeaderPriority:         &PriorityParam{Exclusive: true, Weight: 255},
		},
	}
	defer tr.CloseIdleConnections()
	// Send twice to exercise SETTINGS processing, both HPACK tables and reuse.
	for range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "POST", server.URL, bytes.NewReader(payload))
		req = WithOrderedHeaders(req, []hpack.HeaderField{
			{Name: "x-a", Value: "1"}, {Name: "x-b", Value: "2"}, {Name: "x-a", Value: "3"},
			{Name: "content-length", Value: strconv.Itoa(len(payload))},
		})
		var raw []hpack.HeaderField
		req = WithResponseHeaderSink(req, &raw)
		res, err := tr.RoundTrip(req)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		cancel()
		if err != nil || res.StatusCode != 200 || !bytes.Equal(body, response) {
			t.Fatalf("response: status=%d bytes=%d err=%v", res.StatusCode, len(body), err)
		}
		var cookies []string
		for _, hf := range raw {
			if hf.Name == "set-cookie" {
				cookies = append(cookies, hf.Value)
			}
		}
		if !reflect.DeepEqual(cookies, []string{"one=1", "two=2"}) {
			t.Fatalf("raw response header sink cookies=%v", cookies)
		}
	}
}
