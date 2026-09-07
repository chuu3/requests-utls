package requestsutls

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// A byte limit on each representation does not bound the aggregate memory and
// call depth of arbitrarily many nested decoders.
const maxContentDecodingLayers = 4

// responseLimitReader checks every representation, including the encoded body
// and intermediate layers. A compressed response cannot bypass the body limit.
type responseLimitReader struct {
	r         io.Reader
	remaining int64
}

func (r *responseLimitReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if int64(len(p))-1 > r.remaining {
		p = p[:r.remaining+1]
	}
	n, err := r.r.Read(p)
	if int64(n) > r.remaining {
		return 0, ErrResponseTooLarge
	}
	r.remaining -= int64(n)
	return n, err
}

// readResponseBody does not close or drain res.Body. The transport must retire
// an HTTP/1 connection before closing a body that failed or exceeded its limit.
// Response headers remain the original wire headers even when decoded is true.
func readResponseBody(res *http.Response, limit int64, decode bool) ([]byte, bool, error) {
	if res.ContentLength > limit && res.Body != http.NoBody {
		return nil, false, ErrResponseTooLarge
	}
	wire := &responseLimitReader{r: res.Body, remaining: limit}
	var reader io.Reader = wire
	if !decode {
		data, err := io.ReadAll(reader)
		return data, false, err
	}
	var encodings []string
	for _, value := range res.Header.Values("Content-Encoding") {
		for encoding := range strings.SplitSeq(value, ",") {
			encoding = strings.ToLower(strings.TrimSpace(encoding))
			if encoding != "" && encoding != "identity" {
				if len(encodings) == maxContentDecodingLayers {
					return nil, false, fmt.Errorf("Content-Encoding supports at most %d decoding layers", maxContentDecodingLayers)
				}
				encodings = append(encodings, encoding)
			}
		}
	}
	if len(encodings) == 0 {
		data, err := io.ReadAll(reader)
		return data, false, err
	}
	// HEAD, 204 and 304 may describe an encoded representation without a body.
	buffered := bufio.NewReader(reader)
	if _, err := buffered.Peek(1); err == io.EOF {
		return []byte{}, false, nil
	} else if err != nil {
		return nil, false, err
	}
	reader = buffered
	var closers []func()
	var inputs []io.Reader
	defer func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}()
	for i := len(encodings) - 1; i >= 0; i-- {
		var decoded io.Reader
		input := reader
		switch encodings[i] {
		case "gzip", "x-gzip":
			decoder, err := gzip.NewReader(reader)
			if err != nil {
				return nil, false, fmt.Errorf("decode gzip: %w", err)
			}
			decoded = decoder
			closers = append(closers, func() { decoder.Close() })
		case "deflate":
			// RFC deflate has a zlib wrapper; older servers also send raw DEFLATE.
			// Inspect the wrapper before consuming it, never retry corrupt streams.
			buffered := bufio.NewReader(reader)
			input = buffered
			header, _ := buffered.Peek(2)
			var decoder io.ReadCloser
			if len(header) == 2 && header[0]&15 == 8 && header[0]>>4 <= 7 && (int(header[0])*256+int(header[1]))%31 == 0 {
				var err error
				decoder, err = zlib.NewReader(buffered)
				if err != nil {
					return nil, false, fmt.Errorf("decode deflate: %w", err)
				}
			} else {
				decoder = flate.NewReader(buffered)
			}
			decoded = decoder
			closers = append(closers, func() { decoder.Close() })
		case "br":
			decoded = brotli.NewReader(reader)
		case "zstd":
			// Bound codec window allocation as well as output, with enough room
			// for ordinary frames when callers set a very small response limit.
			memoryLimit := uint64(limit)
			if memoryLimit < 64<<20 {
				memoryLimit = 64 << 20
			}
			decoder, err := zstd.NewReader(reader, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxMemory(memoryLimit))
			if err != nil {
				return nil, false, fmt.Errorf("decode zstd: %w", err)
			}
			decoded = decoder
			closers = append(closers, decoder.Close)
		default:
			return nil, false, fmt.Errorf("unsupported Content-Encoding %q; disable content decoding to read the original bytes", encodings[i])
		}
		reader = &responseLimitReader{r: decoded, remaining: limit}
		inputs = append(inputs, input)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, false, fmt.Errorf("decode response body: %w", err)
	}
	// An inner DEFLATE stream can finish before an outer gzip checksum/footer,
	// or leave unread trailing bytes. Verify every layer, from inside out, so a
	// buffered outer error cannot disappear when the inner decoder returns EOF.
	for i := len(inputs) - 1; i >= 0; i-- {
		if i == 0 && res.ContentLength > 0 && limit-wire.remaining < res.ContentLength {
			return nil, false, fmt.Errorf("content decoder ended before the response body framing")
		}
		var tail [1]byte
		n, err := io.ReadFull(inputs[i], tail[:])
		if n != 0 {
			return nil, false, fmt.Errorf("trailing bytes after compressed response layer")
		}
		if err != io.EOF {
			return nil, false, fmt.Errorf("decode response layer completion: %w", err)
		}
	}
	return data, true, nil
}
