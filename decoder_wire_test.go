package requestsutls

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/chuu3/requests-utls/internal/testserver"
	"golang.org/x/net/http2/hpack"
)

func chunkedEncodedReply(coding string, encoded []byte) string {
	var wire bytes.Buffer
	fmt.Fprintf(&wire, "HTTP/1.1 200 OK\r\nContent-Encoding: %s\r\nTransfer-Encoding: chunked\r\nTrailer: X-Complete\r\n\r\n", coding)
	// Deliberately split codec footers and checksums across HTTP chunks.
	for index := 0; len(encoded) != 0; index++ {
		length := min([]int{1, 2, 7, 3}[index%4], len(encoded))
		fmt.Fprintf(&wire, "%x\r\n", length)
		wire.Write(encoded[:length])
		wire.WriteString("\r\n")
		encoded = encoded[length:]
	}
	wire.WriteString("0\r\nX-Complete: yes\r\n\r\n")
	return wire.String()
}

func TestDecoderWireHTTP1ChunkedTrailersAndPoolReuse(t *testing.T) {
	plain := bytes.Repeat([]byte("你好 — complete compressed HTTP response\n"), 40)
	for _, coding := range []string{"gzip", "deflate", "raw-deflate", "br", "zstd", "deflate,gzip", "gzip,br"} {
		t.Run(coding, func(t *testing.T) {
			encoded := bytes.Clone(plain)
			for _, layer := range strings.Split(coding, ",") {
				encoded = encodeTestBody(t, layer, encoded)
			}
			label := strings.ReplaceAll(coding, "raw-deflate", "deflate")
			wire := chunkedEncodedReply(label, encoded)
			peer := newH1WirePeer(t, true, []string{"http/1.1"}, func(context.Context, h1WireRequest) (string, bool) {
				return wire, false
			})
			session := h1Session(t, peer, nil)
			for range 3 {
				response, err := session.Do(testContext(t), Request{URL: peer.URL})
				if err != nil {
					t.Fatal(err)
				}
				if !response.Decoded || response.Protocol != "HTTP/1.1" || !bytes.Equal(response.Body, plain) {
					t.Fatalf("decoded=%v protocol=%s body length=%d", response.Decoded, response.Protocol, len(response.Body))
				}
				var encoding, transfer, trailer string
				for _, field := range response.Headers {
					switch strings.ToLower(field.Name) {
					case "content-encoding":
						encoding = field.Value
					case "transfer-encoding":
						transfer = field.Value
					case "trailer":
						trailer = field.Value
					}
				}
				if encoding != label || transfer != "chunked" || trailer != "X-Complete" {
					t.Fatalf("decoding changed wire headers: %+v", response.Headers)
				}
			}
			peer.mu.Lock()
			defer peer.mu.Unlock()
			if peer.accepted != 1 || len(peer.hellos) != 1 || len(peer.requests) != 3 {
				t.Fatalf("codec EOF/trailers prevented reuse: connections=%d hellos=%d requests=%d", peer.accepted, len(peer.hellos), len(peer.requests))
			}
		})
	}
}

func TestDecoderWireHTTP2RejectsOuterCorruptionAndKeepsSessionUsable(t *testing.T) {
	plain := []byte("inner DEFLATE has finished, outer gzip must still be validated")
	inner := encodeTestBody(t, "deflate", plain)
	valid := encodeTestBody(t, "gzip", inner)
	checksum := bytes.Clone(valid)
	checksum[len(checksum)-8] ^= 0xff
	truncated := bytes.Clone(valid[:len(valid)-8])
	trailing := encodeTestBody(t, "gzip", append(bytes.Clone(inner), []byte("unexpected decoded outer tail")...))
	server := testServer(t, func(_ context.Context, req testserver.Request) testserver.Response {
		body := valid
		switch req.Header(":path") {
		case "/checksum":
			body = checksum
		case "/truncated":
			body = truncated
		case "/trailing":
			body = trailing
		}
		return testserver.Response{Body: body, Headers: []hpack.HeaderField{{Name: "content-encoding", Value: "deflate,gzip"}}}
	})
	session := testSession(t, server, nil)
	for _, test := range []struct {
		path   string
		target error
	}{
		{"/checksum", gzip.ErrChecksum},
		{"/truncated", io.ErrUnexpectedEOF},
		{"/trailing", nil},
	} {
		response, err := session.Do(testContext(t), Request{URL: server.URL + test.path})
		if err == nil || response != nil || test.target != nil && !errors.Is(err, test.target) {
			t.Fatalf("%s: response=%+v err=%v want=%v", test.path, response, err, test.target)
		}
		response, err = session.Do(testContext(t), Request{URL: server.URL + "/valid"})
		if err != nil || !response.Decoded || !bytes.Equal(response.Body, plain) {
			t.Fatalf("valid request after %s: response=%+v err=%v", test.path, response, err)
		}
	}
	snapshot := server.Snapshot()
	if snapshot.Connections != 1 || len(snapshot.Requests) != 6 {
		t.Fatalf("content errors poisoned shared H2 transport: connections=%d requests=%d", snapshot.Connections, len(snapshot.Requests))
	}
}

func TestDecoderWireLimitsEveryRepresentationAndRecovers(t *testing.T) {
	const limit = 256
	exactPlain := bytes.Repeat([]byte("x"), limit)
	exact := encodeTestBody(t, "gzip", exactPlain)
	expanded := encodeTestBody(t, "gzip", bytes.Repeat([]byte("x"), limit+1))
	// A valid empty DEFLATE stream with large outer-layer padding keeps final
	// decoded output tiny, while its intermediate representation exceeds limit.
	inner := encodeTestBody(t, "deflate", []byte("ok"))
	intermediate := encodeTestBody(t, "gzip", append(inner, bytes.Repeat([]byte("J"), limit*4)...))
	if len(exact) > limit || len(expanded) > limit || len(intermediate) > limit {
		t.Fatal("test does not isolate decoded/intermediate limits from the wire limit")
	}
	for _, protocol := range []string{"h1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			var session *Session
			var baseURL string
			selectBody := func(path string) (string, []byte) {
				switch path {
				case "/expanded":
					return "gzip", expanded
				case "/intermediate":
					return "deflate,gzip", intermediate
				case "/encoded":
					return "identity", bytes.Repeat([]byte("W"), limit+1)
				default:
					return "gzip", exact
				}
			}
			if protocol == "h1" {
				peer := newH1WirePeer(t, true, []string{"http/1.1"}, func(_ context.Context, req h1WireRequest) (string, bool) {
					path := strings.Split(req.Line, " ")[1]
					coding, body := selectBody(path)
					return chunkedEncodedReply(coding, body), false
				})
				session = h1Session(t, peer, func(options *Options) { options.MaxResponseBytes = limit })
				baseURL = peer.URL
			} else {
				server := testServer(t, func(_ context.Context, req testserver.Request) testserver.Response {
					coding, body := selectBody(req.Header(":path"))
					return testserver.Response{Body: body, Headers: []hpack.HeaderField{{Name: "content-encoding", Value: coding}}}
				})
				session = testSession(t, server, func(options *Options) { options.MaxResponseBytes = limit })
				baseURL = server.URL
			}
			for _, path := range []string{"/expanded", "/intermediate", "/encoded"} {
				if response, err := session.Do(testContext(t), Request{URL: baseURL + path}); !errors.Is(err, ErrResponseTooLarge) || response != nil {
					t.Fatalf("%s response=%+v error=%v; expected bounded representation failure", path, response, err)
				}
				response, err := session.Do(testContext(t), Request{URL: baseURL + "/exact"})
				if err != nil || !response.Decoded || !bytes.Equal(response.Body, exactPlain) {
					t.Fatalf("exact-limit request after %s: response=%+v err=%v", path, response, err)
				}
			}
		})
	}
}
