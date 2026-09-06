package requestsutls

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func encodeTestBody(t *testing.T, coding string, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	var writer io.WriteCloser
	switch coding {
	case "gzip":
		writer = gzip.NewWriter(&b)
	case "deflate":
		writer = zlib.NewWriter(&b)
	case "raw-deflate":
		writer, _ = flate.NewWriter(&b, flate.DefaultCompression)
	case "br":
		writer = brotli.NewWriter(&b)
	case "zstd":
		writer, _ = zstd.NewWriter(&b, zstd.WithEncoderConcurrency(1))
	default:
		t.Fatalf("unknown test encoding %s", coding)
	}
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func encodedResponse(coding string, data []byte) *http.Response {
	return &http.Response{Header: http.Header{"Content-Encoding": {coding}}, Body: io.NopCloser(bytes.NewReader(data))}
}

func TestResponseContentDecoding(t *testing.T) {
	plain := bytes.Repeat([]byte("你好 — requests-utls\n"), 100)
	for _, coding := range []string{"gzip", "deflate", "raw-deflate", "br", "zstd"} {
		t.Run(coding, func(t *testing.T) {
			encoded := encodeTestBody(t, coding, plain)
			label := coding
			if coding == "raw-deflate" {
				label = "deflate"
			}
			res := encodedResponse(label, encoded)
			got, decoded, err := readResponseBody(res, 1<<20, true)
			if err != nil || !decoded || !bytes.Equal(got, plain) {
				t.Fatalf("decoded=%v size=%d err=%v", decoded, len(got), err)
			}
			if res.Header.Get("Content-Encoding") != label {
				t.Fatal("wire headers were mutated")
			}
			got, decoded, err = readResponseBody(encodedResponse(label, encoded), 1<<20, false)
			if err != nil || decoded || !bytes.Equal(got, encoded) {
				t.Fatalf("raw response mismatch: %v", err)
			}
			_, _, err = readResponseBody(encodedResponse(label, encoded), int64(len(plain)-1), true)
			if !errors.Is(err, ErrResponseTooLarge) {
				t.Fatalf("output limit: %v", err)
			}
			_, _, err = readResponseBody(encodedResponse(label, encoded), int64(len(encoded)-1), false)
			if !errors.Is(err, ErrResponseTooLarge) {
				t.Fatalf("wire limit: %v", err)
			}
		})
	}
}

func TestResponseStackedContentEncoding(t *testing.T) {
	plain := bytes.Repeat([]byte("ordered encoding\n"), 1000)
	encoded := encodeTestBody(t, "br", encodeTestBody(t, "gzip", plain))
	res := encodedResponse("gzip", encoded)
	res.Header.Add("Content-Encoding", "identity, BR")
	got, decoded, err := readResponseBody(res, 1<<20, true)
	if err != nil || !decoded || !bytes.Equal(got, plain) {
		t.Fatalf("stacked encodings: %v", err)
	}
}

func TestResponseDecodingEdgeCases(t *testing.T) {
	for _, coding := range []string{"gzip", "deflate", "br", "zstd"} {
		got, decoded, err := readResponseBody(encodedResponse(coding, nil), 10, true)
		if err != nil || decoded || len(got) != 0 {
			t.Fatalf("empty %s: %v", coding, err)
		}
		_, _, err = readResponseBody(encodedResponse(coding, []byte("invalid compressed stream")), 1<<20, true)
		if err == nil {
			t.Fatalf("corrupt %s accepted", coding)
		}
	}
	_, _, err := readResponseBody(encodedResponse("future-coding", []byte("raw")), 20, true)
	if err == nil {
		t.Fatal("unknown encoding silently accepted")
	}
	got, decoded, err := readResponseBody(encodedResponse("identity", []byte("1234")), 4, true)
	if err != nil || decoded || string(got) != "1234" {
		t.Fatalf("exact limit: %v", err)
	}
	corrupt := encodeTestBody(t, "deflate", []byte("checksum must be verified"))
	corrupt[len(corrupt)-1] ^= 0xff
	_, _, err = readResponseBody(encodedResponse("deflate", corrupt), 1<<20, true)
	if err == nil {
		t.Fatal("corrupt zlib checksum accepted as raw DEFLATE")
	}
}

func TestResponseDecoderVerifiesEveryLayer(t *testing.T) {
	plain := []byte("small body")
	inner := encodeTestBody(t, "deflate", plain)
	t.Run("encoded trailing bytes cannot bypass limit", func(t *testing.T) {
		wire := append(inner, bytes.Repeat([]byte("J"), 20000)...)
		_, _, err := readResponseBody(encodedResponse("deflate", wire), 8192, true)
		if err == nil {
			t.Fatal("trailing representation accepted")
		}
	})
	for _, corruption := range []string{"checksum", "truncated"} {
		t.Run(corruption, func(t *testing.T) {
			wire := encodeTestBody(t, "gzip", inner)
			if corruption == "checksum" {
				wire[len(wire)-8] ^= 0xff
			} else {
				wire = wire[:len(wire)-8]
			}
			_, _, err := readResponseBody(encodedResponse("deflate,gzip", wire), 8192, true)
			if err == nil {
				t.Fatal("outer coding corruption hidden by inner DEFLATE EOF")
			}
		})
	}
}
