package http2

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
)

// Exercise the actual frame reader, retry classification and body rewind. A
// server may receive bytes without processing a request: LastStreamID is the
// protocol's boundary, not whether the client's body writer has run.
func TestGoAwayRetriesOnlyUnprocessedPost(t *testing.T) {
	for _, tc := range []struct {
		name         string
		last         uint32
		code         ErrCode
		wantAttempts int32
		wantSuccess  bool
		retryLimit   int
		alwaysGoAway bool
	}{
		{"unprocessed graceful POST retries", 0, ErrCodeNo, 2, true, 0, false},
		{"processed graceful POST not replayed", 1, ErrCodeNo, 1, false, 8, false},
		{"protocol error not replayed", 0, ErrCodeProtocol, 1, false, 8, false},
		{"retries disabled", 0, ErrCodeNo, 1, false, -1, false},
		{"retries exhausted", 0, ErrCodeNo, 2, false, 1, true},
		{"invalid retry bound rejected", 0, ErrCodeNo, 0, false, 33, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const payload = "owned-post-body-snapshot"
			var attempts atomic.Int32
			serverErrors := make(chan error, 8)
			tr := &Transport{
				WireProfile:           &WireProfile{Settings: []Setting{{SettingEnablePush, 0}}},
				MaxUnprocessedRetries: tc.retryLimit,
				DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
					client, server := net.Pipe()
					attempt := attempts.Add(1)
					go func() {
						defer server.Close()
						server.SetDeadline(time.Now().Add(5 * time.Second))
						serverErrors <- serveGoAwayPost(server, attempt == 1 || tc.alwaysGoAway, tc.last, tc.code, payload)
					}()
					return client, nil
				},
			}
			defer tr.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "POST", "https://example.com/submit", strings.NewReader(payload))
			req = WithOrderedHeaders(req, []hpack.HeaderField{{Name: "x-request-id", Value: "one"}})
			res, err := tr.RoundTrip(req)
			if res != nil {
				res.Body.Close()
			}
			if (err == nil) != tc.wantSuccess {
				t.Fatalf("RoundTrip success=%v, want %v: %v", err == nil, tc.wantSuccess, err)
			}
			if got := attempts.Load(); got != tc.wantAttempts {
				t.Fatalf("POST attempts=%d, want %d (err=%v)", got, tc.wantAttempts, err)
			}
			for range tc.wantAttempts {
				if err := <-serverErrors; err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestGoAwayLastStreamBoundaryAndProtocolErrors(t *testing.T) {
	for _, code := range []ErrCode{ErrCodeNo, ErrCodeProtocol} {
		cc := &ClientConn{streams: make(map[uint32]*clientStream)}
		for _, id := range []uint32{1, 3, 5} {
			cc.streams[id] = &clientStream{cc: cc, ID: id, abort: make(chan struct{})}
		}
		cc.setGoAway(&GoAwayFrame{FrameHeader: FrameHeader{valid: true}, LastStreamID: 3, ErrCode: code})
		for _, id := range []uint32{1, 3} {
			if cc.streams[id].abortErr != nil {
				t.Fatalf("GOAWAY %v aborted possibly processed stream %d", code, id)
			}
		}
		err := cc.streams[5].abortErr
		if err == nil || canRetryError(err) != (code == ErrCodeNo) {
			t.Fatalf("GOAWAY %v affected higher stream: err=%v retry=%v", code, err, canRetryError(err))
		}
	}
}

func serveGoAwayPost(conn net.Conn, first bool, last uint32, code ErrCode, wantBody string) error {
	preface := make([]byte, len(ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return err
	}
	if string(preface) != ClientPreface {
		return fmt.Errorf("wrong preface")
	}
	fr := NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	f, err := fr.ReadFrame()
	if err != nil {
		return err
	}
	if _, ok := f.(*SettingsFrame); !ok {
		return fmt.Errorf("initial frame %T", f)
	}
	if err := fr.WriteSettings(Setting{SettingMaxConcurrentStreams, 100}); err != nil {
		return err
	}
	var body []byte
	var stream uint32
	var bodyComplete, settingsAck bool
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return err
		}
		switch f := f.(type) {
		case *MetaHeadersFrame:
			stream = f.StreamID
			if f.PseudoValue("method") != "POST" {
				return fmt.Errorf("method changed on retry")
			}
		case *SettingsFrame:
			settingsAck = f.IsAck()
		case *DataFrame:
			body = append(body, f.Data()...)
			bodyComplete = f.StreamEnded()
		}
		// net.Pipe is unbuffered: consume the client's SETTINGS ACK before
		// writing GOAWAY so the client's read loop is free to read it.
		if bodyComplete && settingsAck {
			if string(body) != wantBody {
				return fmt.Errorf("POST body=%q, want %q", body, wantBody)
			}
			if first {
				return fr.WriteGoAway(last, code, nil)
			}
			var block bytes.Buffer
			enc := hpack.NewEncoder(&block)
			enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
			return fr.WriteHeaders(HeadersFrameParam{StreamID: stream, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true})
		}
	}
}
