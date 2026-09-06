package http2

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2/hpack"
	"requests-utls/internal/h2/internal/httpcommon"
)

type orderedHeadersKey struct{}
type responseHeaderSinkKey struct{}

type orderedHeaders struct{ fields []hpack.HeaderField }

// WithOrderedHeaders returns a request using an immutable copy of fields as its
// complete regular wire header list. Header order and interleaved duplicate
// fields are preserved, including cookie fields. No default headers are added.
// Names must be lowercase; pseudo-headers come from Request and WireProfile.
// Request.Header remains available for ancillary upstream behavior, but is not
// the source used for HPACK serialization. Request body ownership is unchanged.
func WithOrderedHeaders(req *http.Request, fields []hpack.HeaderField) *http.Request {
	copyFields := append([]hpack.HeaderField(nil), fields...)
	ctx := context.WithValue(req.Context(), orderedHeadersKey{}, orderedHeaders{copyFields})
	return req.Clone(ctx)
}

// WithResponseHeaderSink preserves final regular response headers in wire order.
// The sink belongs to this individual request. It is written once before
// RoundTrip returns successfully and is not modified afterward. The caller must
// not read the sink until RoundTrip returns or reuse it in concurrent requests.
// Informational headers and trailers are not included.
func WithResponseHeaderSink(req *http.Request, sink *[]hpack.HeaderField) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), responseHeaderSinkKey{}, sink))
}

func getOrderedHeaders(req *http.Request) ([]hpack.HeaderField, bool) {
	value, ok := req.Context().Value(orderedHeadersKey{}).(orderedHeaders)
	return value.fields, ok
}

func encodeOrderedRequestHeaders(req *http.Request, fields []hpack.HeaderField, profile *WireProfile, peerMaxHeaderListSize uint64, emit func(hpack.HeaderField)) (httpcommon.EncodeHeadersResult, error) {
	var result httpcommon.EncodeHeadersResult
	if len(req.Trailer) != 0 {
		return result, fmt.Errorf("ordered request trailers are not supported")
	}
	// Reuse upstream's URL, authority and pseudo-path validation. This pass does
	// not mutate HPACK state. Regular fields never enter the map-based encoder.
	pseudo := make(map[string]string, 4)
	result, err := httpcommon.EncodeHeaders(context.Background(), httpcommon.EncodeHeadersParam{
		Request: httpcommon.Request{
			URL: req.URL, Host: req.Host, Method: req.Method,
			ActualContentLength: actualContentLength(req),
		},
	}, func(name, value string) {
		if strings.HasPrefix(name, ":") {
			pseudo[name] = value
		}
	})
	if err != nil {
		return result, err
	}
	order := []string{":authority", ":method", ":path", ":scheme"}
	if profile != nil && len(profile.PseudoHeaderOrder) != 0 {
		order = profile.PseudoHeaderOrder
	}
	all := make([]hpack.HeaderField, 0, len(pseudo)+len(fields))
	for _, name := range order {
		if value, ok := pseudo[name]; ok {
			all = append(all, hpack.HeaderField{Name: name, Value: value})
		}
	}
	seenContentLength := false
	for i, hf := range fields {
		if !validWireHeaderFieldName(hf.Name) {
			return result, fmt.Errorf("ordered headers[%d]: invalid lowercase regular header name %q", i, hf.Name)
		}
		if !httpguts.ValidHeaderFieldValue(hf.Value) || strings.Trim(hf.Value, " \t") != hf.Value {
			return result, fmt.Errorf("ordered headers[%d]: invalid value for %q", i, hf.Name)
		}
		switch hf.Name {
		case "host":
			return result, fmt.Errorf("ordered headers[%d]: set Request.Host instead of the host header", i)
		case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":
			return result, fmt.Errorf("ordered headers[%d]: connection-specific header %q is forbidden in HTTP/2", i, hf.Name)
		case "te":
			if hf.Value != "trailers" {
				return result, fmt.Errorf("ordered headers[%d]: HTTP/2 te must be trailers", i)
			}
		case "trailer":
			return result, fmt.Errorf("ordered request trailers are not supported")
		case "content-length":
			if seenContentLength {
				return result, fmt.Errorf("ordered headers[%d]: repeated content-length is not supported", i)
			}
			seenContentLength = true
			if hf.Value == "" || strings.IndexFunc(hf.Value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				return result, fmt.Errorf("ordered headers[%d]: invalid content-length", i)
			}
			length, err := strconv.ParseInt(hf.Value, 10, 64)
			if err != nil || length != actualContentLength(req) {
				return result, fmt.Errorf("ordered headers[%d]: content-length does not match request body", i)
			}
		}
		all = append(all, hf)
	}
	var size uint64
	for _, hf := range all {
		size += uint64(len(hf.Name)) + uint64(len(hf.Value)) + 32
	}
	// peerMaxHeaderListSize is initialized to MaxUint64. Unlike the upstream
	// helper, a peer's explicit zero is a zero-sized limit, not "unlimited".
	if size > peerMaxHeaderListSize {
		return result, httpcommon.ErrRequestHeaderListSize
	}
	trace := httptrace.ContextClientTrace(req.Context())
	for _, hf := range all {
		emit(hf)
		if trace != nil && trace.WroteHeaderField != nil {
			trace.WroteHeaderField(hf.Name, []string{hf.Value})
		}
	}
	return result, nil
}
