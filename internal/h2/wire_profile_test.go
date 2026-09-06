package http2

import (
	"bufio"
	"bytes"
	"io"
	"math"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
)

func TestOrderedHeadersPreserveInterleavedDuplicates(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.com/a?b=c", nil)
	headers := []hpack.HeaderField{
		{Name: "x-a", Value: "1"},
		{Name: "cookie", Value: "a=1; b=2", Sensitive: true},
		{Name: "x-b", Value: "2"},
		{Name: "x-a", Value: "3"},
		{Name: "cookie", Value: "c=3"},
	}
	req = WithOrderedHeaders(req, headers)
	headers[0].Value = "mutated after snapshot"
	fields, ok := getOrderedHeaders(req)
	if !ok || fields[0].Value != "1" {
		t.Fatal("ordered request did not snapshot headers")
	}
	profile := &WireProfile{PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"}}
	var encoded bytes.Buffer
	encoder := hpack.NewEncoder(&encoded)
	_, err := encodeOrderedRequestHeaders(req, fields, profile, math.MaxUint64, func(hf hpack.HeaderField) {
		if err := encoder.WriteField(hf); err != nil {
			t.Fatal(err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	decoder := hpack.NewDecoder(4096, nil)
	got, err := decoder.DecodeFull(encoded.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	want := append([]hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/a?b=c"},
	}, fields...)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded fields = %#v, want %#v", got, want)
	}
}

func TestOrderedHeaderValidationDoesNotPolluteHPACK(t *testing.T) {
	cases := []struct {
		name   string
		fields []hpack.HeaderField
		limit  uint64
	}{
		{"uppercase", []hpack.HeaderField{{Name: "X-A", Value: "1"}}, math.MaxUint64},
		{"pseudo", []hpack.HeaderField{{Name: ":method", Value: "GET"}}, math.MaxUint64},
		{"newline", []hpack.HeaderField{{Name: "x-a", Value: "1\r\n2"}}, math.MaxUint64},
		{"whitespace", []hpack.HeaderField{{Name: "x-a", Value: " 1"}}, math.MaxUint64},
		{"connection", []hpack.HeaderField{{Name: "connection", Value: "keep-alive"}}, math.MaxUint64},
		{"transfer encoding", []hpack.HeaderField{{Name: "transfer-encoding", Value: "chunked"}}, math.MaxUint64},
		{"host", []hpack.HeaderField{{Name: "host", Value: "other.example"}}, math.MaxUint64},
		{"te", []hpack.HeaderField{{Name: "te", Value: "gzip"}}, math.MaxUint64},
		{"content length", []hpack.HeaderField{{Name: "content-length", Value: "1"}}, math.MaxUint64},
		{"duplicate content length", []hpack.HeaderField{{Name: "content-length", Value: "0"}, {Name: "content-length", Value: "0"}}, math.MaxUint64},
		{"peer zero limit", nil, 0},
		{"peer small limit", nil, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "https://example.com/", nil)
			emitted := 0
			_, err := encodeOrderedRequestHeaders(req, tc.fields, nil, tc.limit, func(hpack.HeaderField) { emitted++ })
			if err == nil || emitted != 0 {
				t.Fatalf("err=%v, emitted=%d; invalid input must not mutate HPACK", err, emitted)
			}
		})
	}
}

func TestOrderedHeadersContentLengthAndConnect(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://example.com/", strings.NewReader("abc"))
	var got []hpack.HeaderField
	res, err := encodeOrderedRequestHeaders(req, []hpack.HeaderField{{Name: "content-length", Value: "3"}}, nil, math.MaxUint64, func(hf hpack.HeaderField) { got = append(got, hf) })
	if err != nil || !res.HasBody || len(got) != 5 {
		t.Fatalf("res=%+v, headers=%v, err=%v", res, got, err)
	}
	req, _ = http.NewRequest("CONNECT", "https://example.com:443", nil)
	got = nil
	_, err = encodeOrderedRequestHeaders(req, nil, &WireProfile{PseudoHeaderOrder: []string{":method", ":authority", ":scheme", ":path"}}, math.MaxUint64, func(hf hpack.HeaderField) { got = append(got, hf) })
	want := []hpack.HeaderField{{Name: ":method", Value: "CONNECT"}, {Name: ":authority", Value: "example.com:443"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("CONNECT headers=%v, err=%v", got, err)
	}
}

type wireRecordingConn struct {
	mu     sync.Mutex
	output bytes.Buffer
	closed chan struct{}
	once   sync.Once
}

func newWireRecordingConn() *wireRecordingConn {
	return &wireRecordingConn{closed: make(chan struct{})}
}
func (c *wireRecordingConn) Read([]byte) (int, error) { <-c.closed; return 0, io.EOF }
func (c *wireRecordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.output.Write(p)
}
func (c *wireRecordingConn) Close() error                     { c.once.Do(func() { close(c.closed) }); return nil }
func (c *wireRecordingConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *wireRecordingConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *wireRecordingConn) SetDeadline(time.Time) error      { return nil }
func (c *wireRecordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *wireRecordingConn) SetWriteDeadline(time.Time) error { return nil }
func (c *wireRecordingConn) snapshot() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.output.Bytes()...)
}

func TestWireProfileExactSettingsAndZeroSemantics(t *testing.T) {
	for _, update := range []uint32{0, 1000} {
		t.Run(strconv.FormatUint(uint64(update), 10), func(t *testing.T) {
			profile := &WireProfile{
				Settings: []Setting{
					{SettingHeaderTableSize, 0}, {SettingEnablePush, 0},
					{SettingInitialWindowSize, 0}, {SettingMaxFrameSize, 32768},
					{SettingMaxHeaderListSize, 0},
				},
				ConnectionWindowUpdate: update,
			}
			conn := newWireRecordingConn()
			cc, err := (&Transport{WireProfile: profile}).NewClientConn(conn)
			if err != nil {
				t.Fatal(err)
			}
			defer cc.Close()
			if cc.initialStreamRecvWindowSize != 0 || cc.fr.maxReadSize != 32768 || cc.fr.maxHeaderListSize() != 0 {
				t.Fatalf("wire settings differ from actual receive state: stream=%d frame=%d header limit=%d", cc.initialStreamRecvWindowSize, cc.fr.maxReadSize, cc.fr.maxHeaderListSize())
			}
			if cc.inflow.avail != int32(initialWindowSize+update) {
				t.Fatalf("connection window = %d", cc.inflow.avail)
			}
			data := conn.snapshot()
			if !bytes.HasPrefix(data, []byte(ClientPreface)) {
				t.Fatal("missing connection preface")
			}
			fr := NewFramer(nil, bytes.NewReader(data[len(ClientPreface):]))
			f, err := fr.ReadFrame()
			if err != nil {
				t.Fatal(err)
			}
			sf, ok := f.(*SettingsFrame)
			if !ok {
				t.Fatalf("first frame is %T", f)
			}
			var settings []Setting
			sf.ForeachSetting(func(s Setting) error { settings = append(settings, s); return nil })
			if !reflect.DeepEqual(settings, profile.Settings) {
				t.Fatalf("settings=%v, want=%v", settings, profile.Settings)
			}
			if update != 0 {
				f, err = fr.ReadFrame()
				if err != nil {
					t.Fatal(err)
				}
				wu, ok := f.(*WindowUpdateFrame)
				if !ok || wu.StreamID != 0 || wu.Increment != update {
					t.Fatalf("window update=%v", f)
				}
			}
			if _, err := fr.ReadFrame(); err != io.EOF {
				t.Fatalf("unexpected extra frame or error: %v", err)
			}
		})
	}
}

func TestWireProfileOmittedSettingsUseProtocolDefaults(t *testing.T) {
	conn := newWireRecordingConn()
	cc, err := (&Transport{WireProfile: &WireProfile{Settings: []Setting{{SettingEnablePush, 0}}}}).NewClientConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	if cc.initialStreamRecvWindowSize != 65535 || cc.fr.maxReadSize != 16384 {
		t.Fatalf("absent settings use non-protocol defaults: stream=%d, frame=%d", cc.initialStreamRecvWindowSize, cc.fr.maxReadSize)
	}
}

func TestWireProfileValidation(t *testing.T) {
	bad := []*WireProfile{
		{},
		{Settings: []Setting{{SettingEnablePush, 1}}},
		{Settings: []Setting{{SettingEnablePush, 0}, {SettingEnablePush, 0}}},
		{Settings: []Setting{{SettingEnablePush, 0}, {SettingInitialWindowSize, 1 << 31}}},
		{Settings: []Setting{{SettingEnablePush, 0}, {SettingMaxFrameSize, 1}}},
		{Settings: []Setting{{SettingEnablePush, 0}}, ConnectionWindowUpdate: math.MaxInt32},
		{Settings: []Setting{{SettingEnablePush, 0}}, PseudoHeaderOrder: []string{":method"}},
		{Settings: []Setting{{SettingEnablePush, 0}}, PseudoHeaderOrder: []string{":method", ":method", ":path", ":scheme"}},
		{Settings: []Setting{{SettingEnablePush, 0}}, HeaderPriority: &PriorityParam{StreamDep: 1 << 31}},
	}
	for i, profile := range bad {
		if err := profile.Validate(); err == nil {
			t.Fatalf("invalid profile %d accepted", i)
		}
	}
}

func TestHeaderPriorityFragmentationAndExplicitZero(t *testing.T) {
	var output bytes.Buffer
	cc := &ClientConn{bw: bufio.NewWriter(&output)}
	cc.fr = NewFramer(cc.bw, nil)
	block := bytes.Repeat([]byte{'x'}, 20000)
	if err := cc.writeHeaders(1, true, 16384, block, &PriorityParam{}); err != nil {
		t.Fatal(err)
	}
	fr := NewFramer(nil, bytes.NewReader(output.Bytes()))
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	hf := f.(*HeadersFrame)
	if !hf.HasPriority() || hf.Length != 16384 || hf.Priority != (PriorityParam{}) || hf.HeadersEnded() || !hf.StreamEnded() {
		t.Fatalf("invalid first HEADERS frame: %+v", hf)
	}
	got := append([]byte(nil), hf.HeaderBlockFragment()...)
	f, err = fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	cf := f.(*ContinuationFrame)
	got = append(got, cf.HeaderBlockFragment()...)
	if !cf.HeadersEnded() || !bytes.Equal(got, block) {
		t.Fatal("continuation did not preserve block")
	}
}

func TestOrderedRequestsOnlyRetryProvenUnprocessed(t *testing.T) {
	for _, method := range []string{"GET", "POST", "DELETE"} {
		req, _ := http.NewRequest(method, "https://example.com/", nil)
		req = WithOrderedHeaders(req, nil)
		for _, original := range []error{errClientConnUnusable, errClientConnGotGoAway, StreamError{StreamID: 1, Code: ErrCodeRefusedStream}} {
			got, err := shouldRetryRequest(req, original)
			if got != req || err != nil {
				t.Fatalf("%s: proven unprocessed error %v: request=%v err=%v", method, original, got, err)
			}
		}
		for _, original := range []error{io.EOF, io.ErrUnexpectedEOF, errClientConnNotEstablished, StreamError{StreamID: 1, Code: ErrCodeProtocol}, GoAwayError{LastStreamID: 1, ErrCode: ErrCodeNo}} {
			got, err := shouldRetryRequest(req, original)
			if got != nil || err != original {
				t.Fatalf("%s: ambiguous or processed error replayed: request=%v err=%v original=%v", method, got, err, original)
			}
		}
	}
}

func TestWireProfileRejectsBeforeWritingConnection(t *testing.T) {
	conn := newWireRecordingConn()
	_, err := (&Transport{WireProfile: &WireProfile{}}).NewClientConn(conn)
	if err == nil || len(conn.snapshot()) != 0 {
		t.Fatalf("invalid profile wrote connection bytes or succeeded: %v", err)
	}
	select {
	case <-conn.closed:
	default:
		t.Fatal("invalid profile leaked supplied connection")
	}
}
