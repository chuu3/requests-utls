package http2

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
)

type pushWireResult struct {
	settings       []Setting
	resets         []RSTStreamFrame
	windowReturned uint32
	requests       int
	err            error
}

func TestWirePushPromisesAreCanceledWithoutChangingSettingsOrHPACK(t *testing.T) {
	firefox := []Setting{{SettingHeaderTableSize, 65536}, {SettingInitialWindowSize, 131072}, {SettingMaxFrameSize, 16384}}
	for _, test := range []struct {
		name     string
		settings []Setting
	}{
		{"omitted defaults to enabled", firefox},
		{"explicit enabled", append(append([]Setting(nil), firefox...), Setting{SettingEnablePush, 1})},
		{"empty SETTINGS", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			tr, results, attempts := newPushWireTransport(t, &WireProfile{Settings: test.settings}, "valid")
			for range 2 {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				req, _ := http.NewRequestWithContext(ctx, "GET", "https://example.test/parent", nil)
				req = WithOrderedHeaders(req, nil)
				var fields []hpack.HeaderField
				req = WithResponseHeaderSink(req, &fields)
				res, err := tr.RoundTrip(req)
				if err != nil {
					cancel()
					t.Fatal(err)
				}
				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				cancel()
				if err != nil || string(body) != "parent" {
					t.Fatalf("body=%q error=%v", body, err)
				}
				if res.Header.Get("X-Promise-Table") != "promise-indexed-value" || res.Header.Get("X-Pushed-Response") != "response-indexed-value" {
					t.Fatalf("discarding push desynchronized the shared HPACK table: %+v", res.Header)
				}
				for _, field := range fields {
					if field.Name == "set-cookie" {
						t.Fatal("pushed response cookie leaked into parent response")
					}
				}
			}
			tr.CloseIdleConnections()
			result := waitPushResult(t, results)
			if result.err != nil {
				t.Fatal(result.err)
			}
			if !reflect.DeepEqual(result.settings, test.settings) {
				t.Fatalf("SETTINGS changed: got=%v want=%v", result.settings, test.settings)
			}
			if len(result.resets) != 1 || result.resets[0].StreamID != 100 || result.resets[0].ErrCode != ErrCodeCancel {
				t.Fatalf("promised stream not declined with CANCEL: %+v", result.resets)
			}
			if result.windowReturned < 32768 {
				t.Fatalf("discarded push DATA lost connection flow-control credit: %d", result.windowReturned)
			}
			if result.requests != 2 || attempts.Load() != 1 {
				t.Fatalf("requests=%d connections=%d", result.requests, attempts.Load())
			}
		})
	}
}

func TestWirePushPromiseProtocolAndCompressionFailures(t *testing.T) {
	for _, test := range []struct {
		name, mode string
		profile    *WireProfile
		want       ErrCode
	}{
		{"default transport disables push", "valid", nil, ErrCodeProtocol},
		{"explicit zero disables push", "valid", &WireProfile{Settings: []Setting{{SettingEnablePush, 0}}}, ErrCodeProtocol},
		{"promised ID must be even", "odd-id", &WireProfile{}, ErrCodeProtocol},
		{"promised ID must be unused", "reused-id", &WireProfile{}, ErrCodeProtocol},
		{"parent cannot be idle", "idle-parent", &WireProfile{}, ErrCodeProtocol},
		{"continuation must use parent ID", "wrong-continuation", &WireProfile{}, ErrCodeProtocol},
		{"invalid HPACK closes connection", "invalid-hpack", &WireProfile{}, ErrCodeCompression},
	} {
		t.Run(test.name, func(t *testing.T) {
			tr, results, _ := newPushWireTransport(t, test.profile, test.mode)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "GET", "https://example.test/parent", nil)
			res, err := tr.RoundTrip(WithOrderedHeaders(req, nil))
			if res != nil {
				res.Body.Close()
			}
			var code ConnectionError
			if !errors.As(err, &code) || ErrCode(code) != test.want {
				t.Fatalf("error=%v want connection %v", err, test.want)
			}
			tr.CloseIdleConnections()
			// Protocol failures deliberately interrupt the peer's batched writes.
			waitPushResult(t, results)
		})
	}
}

func newPushWireTransport(t *testing.T, profile *WireProfile, mode string) (*Transport, <-chan pushWireResult, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan pushWireResult, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			results <- pushWireResult{err: err}
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		results <- serveCanceledPush(conn, mode)
	}()
	var attempts atomic.Int32
	tr := &Transport{WireProfile: profile, MaxUnprocessedRetries: -1, DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
		attempts.Add(1)
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}}
	t.Cleanup(func() { tr.CloseIdleConnections(); listener.Close() })
	return tr, results, &attempts
}

func waitPushResult(t *testing.T, results <-chan pushWireResult) pushWireResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(6 * time.Second):
		t.Fatal("push peer did not finish")
		return pushWireResult{}
	}
}

func serveCanceledPush(conn net.Conn, mode string) (result pushWireResult) {
	preface := make([]byte, len(ClientPreface))
	if _, result.err = io.ReadFull(conn, preface); result.err != nil {
		return
	}
	if string(preface) != ClientPreface {
		result.err = errors.New("wrong client preface")
		return
	}
	fr := NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	first, err := fr.ReadFrame()
	if err != nil {
		result.err = err
		return
	}
	settings, ok := first.(*SettingsFrame)
	if !ok {
		result.err = fmt.Errorf("initial frame is %T", first)
		return
	}
	settings.ForeachSetting(func(s Setting) error { result.settings = append(result.settings, s); return nil })
	if result.err = fr.WriteSettings(); result.err != nil {
		return
	}
	if result.err = fr.WriteSettingsAck(); result.err != nil {
		return
	}
	var encoded bytes.Buffer
	encoder := hpack.NewEncoder(&encoded)
	encode := func(fields ...hpack.HeaderField) []byte {
		encoded.Reset()
		for _, field := range fields {
			encoder.WriteField(field)
		}
		return bytes.Clone(encoded.Bytes())
	}
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			if err != io.EOF {
				result.err = err
			}
			return
		}
		switch frame := frame.(type) {
		case *RSTStreamFrame:
			result.resets = append(result.resets, *frame)
		case *WindowUpdateFrame:
			if frame.StreamID == 0 {
				result.windowReturned += frame.Increment
			}
		case *MetaHeadersFrame:
			result.requests++
			for _, field := range frame.Fields {
				if field.Name == "cookie" {
					result.err = errors.New("push introduced a cookie into the next request")
					return
				}
			}
			parent := frame.StreamID
			var packet bytes.Buffer
			writer := NewFramer(&packet, nil)
			if result.requests == 1 {
				promised := uint32(100) // deliberately above the client's next stream ID
				if mode == "odd-id" {
					promised = 101
				}
				if mode == "idle-parent" {
					parent += 2
				}
				block := encode(hpack.HeaderField{Name: ":method", Value: "GET"}, hpack.HeaderField{Name: ":scheme", Value: "https"}, hpack.HeaderField{Name: ":authority", Value: "example.test"}, hpack.HeaderField{Name: ":path", Value: "/pushed"}, hpack.HeaderField{Name: "x-promise-table", Value: "promise-indexed-value"})
				if mode == "invalid-hpack" {
					block = []byte{0x80}
				}
				split := len(block) / 2
				writer.WritePushPromise(PushPromiseParam{StreamID: parent, PromiseID: promised, BlockFragment: block[:split], EndHeaders: false})
				continuation := parent
				if mode == "wrong-continuation" {
					continuation += 2
				}
				writer.WriteContinuation(continuation, true, block[split:])
				if mode == "reused-id" {
					block = encode(hpack.HeaderField{Name: ":method", Value: "GET"}, hpack.HeaderField{Name: ":scheme", Value: "https"}, hpack.HeaderField{Name: ":authority", Value: "example.test"}, hpack.HeaderField{Name: ":path", Value: "/again"})
					writer.WritePushPromise(PushPromiseParam{StreamID: parent, PromiseID: promised, BlockFragment: block, EndHeaders: true})
				}
				if mode == "valid" {
					// Queue these frames before the client applies CANCEL. Their
					// HPACK entries and connection DATA credit must still be read.
					block = encode(hpack.HeaderField{Name: ":status", Value: "200"}, hpack.HeaderField{Name: "set-cookie", Value: "push=must-not-escape"}, hpack.HeaderField{Name: "x-pushed-response", Value: "response-indexed-value"})
					writer.WriteHeaders(HeadersFrameParam{StreamID: promised, BlockFragment: block, EndHeaders: true})
					body := bytes.Repeat([]byte("p"), 60000)
					for len(body) != 0 {
						length := min(len(body), 16384)
						writer.WriteData(promised, length == len(body), body[:length])
						body = body[length:]
					}
				}
			}
			if mode == "valid" {
				block := encode(hpack.HeaderField{Name: ":status", Value: "200"}, hpack.HeaderField{Name: "x-promise-table", Value: "promise-indexed-value"}, hpack.HeaderField{Name: "x-pushed-response", Value: "response-indexed-value"})
				writer.WriteHeaders(HeadersFrameParam{StreamID: frame.StreamID, BlockFragment: block, EndHeaders: true})
				writer.WriteData(frame.StreamID, true, []byte("parent"))
			}
			if _, err := io.Copy(conn, strings.NewReader(packet.String())); err != nil {
				result.err = err
				return
			}
		}
	}
}
