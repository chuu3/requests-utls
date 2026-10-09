package http2

import (
	"bytes"
	"math"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func TestSecurityResponseFramingHeaders(t *testing.T) {
	for _, test := range []struct {
		name    string
		lengths []string
		want    string
	}{
		{"identical", []string{"5", "5"}, "5"},
		{"conflicting", []string{"5", "6"}, ""},
		{"invalid", []string{"-1"}, ""},
		{"overflow", []string{"9223372036854775808"}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			cc, _ := lifetimeTestConn(t)
			req, _ := http.NewRequest("GET", "https://example.test/", nil)
			var raw []hpack.HeaderField
			req = WithResponseHeaderSink(req, &raw)
			cs := &clientStream{cc: cc, ID: 1, ctx: req.Context(), respHeaderRecv: make(chan struct{})}
			cc.streams[1] = cs
			fields := []hpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "set-cookie", Value: "a=1"}}
			for _, name := range connHeaders {
				fields = append(fields, hpack.HeaderField{Name: strings.ToLower(name), Value: "invalid-in-h2"})
			}
			for _, value := range test.lengths {
				fields = append(fields, hpack.HeaderField{Name: "content-length", Value: value})
			}
			fields = append(fields, hpack.HeaderField{Name: "set-cookie", Value: "b=2"})
			frame := &MetaHeadersFrame{HeadersFrame: &HeadersFrame{FrameHeader: FrameHeader{StreamID: 1}}, Fields: fields}
			if err := (&clientConnReadLoop{cc: cc}).processHeaders(frame); err != nil {
				t.Fatal(err)
			}
			for _, name := range connHeaders {
				if _, ok := cs.res.Header[name]; ok {
					t.Fatalf("unsafe header retained: %s", name)
				}
			}
			if got := cs.res.Header.Get("Content-Length"); got != test.want {
				t.Fatalf("length=%q want %q", got, test.want)
			}
			want := []hpack.HeaderField{{Name: "set-cookie", Value: "a=1"}}
			if test.want != "" {
				want = append(want, hpack.HeaderField{Name: "content-length", Value: test.want})
			}
			want = append(want, hpack.HeaderField{Name: "set-cookie", Value: "b=2"})
			if !reflect.DeepEqual(raw, want) {
				t.Fatalf("raw headers=%v want %v", raw, want)
			}
		})
	}
}

func TestSecurityTrailerDeclarationBudget(t *testing.T) {
	var block, wire bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "trailer", Value: strings.Repeat("x,", 100) + "y"}} {
		if err := enc.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err := NewFramer(&wire, nil).WriteHeaders(HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	fr := NewFramer(nil, &wire)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	fr.MaxHeaderListSize = 512 // Fits the literal header, but not the declared trailer map.
	frame, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if !frame.(*MetaHeadersFrame).Truncated {
		t.Fatal("trailer declarations bypassed the header memory budget")
	}
}

func TestSecurityHeaderBudgetDoesNotOverflow(t *testing.T) {
	var block, wire bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "x-test", Value: "value"}} {
		if err := enc.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err := NewFramer(&wire, nil).WriteHeaders(HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	fr := NewFramer(nil, &wire)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	fr.MaxHeaderListSize = 1 << 31 // Summing two uint32 budgets would wrap to zero.
	if _, err := fr.ReadFrame(); err != nil {
		t.Fatal(err)
	}
}

func TestSecurityWindowChangeOverflow(t *testing.T) {
	var conn connOutflow
	conn.init()
	stream := outflow{conn: &conn}
	if !stream.add(math.MaxInt32 - initialWindowSize) {
		t.Fatal("valid stream window rejected")
	}
	if !conn.changeInitialWindowSize(initialWindowSize + 1) {
		t.Fatal("valid initial window rejected")
	}
	if _, ok := stream.available(); ok || !conn.flowErr {
		t.Fatal("lazy stream overflow not detected")
	}
	if _, ok := (&outflow{conn: &conn}).available(); ok {
		t.Fatal("connection flow error did not stop sibling writes")
	}
}
