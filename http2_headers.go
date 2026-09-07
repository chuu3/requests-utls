package requestsutls

import (
	"fmt"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// normalizeHTTP2Headers works on the request snapshot, before ordering. Host
// has already supplied req.Host (:authority); it never becomes a regular H2
// field. Connection options remove every occurrence of their named field.
// The bool prevents regeneration of a Connection-nominated Content-Length;
// HTTP/2 can frame the body without that optional regular field.
func normalizeHTTP2Headers(headers []HeaderField) ([]HeaderField, bool, error) {
	drop := map[string]bool{
		"host": true, "connection": true, "keep-alive": true,
		"proxy-connection": true, "transfer-encoding": true,
		"upgrade": true, "http2-settings": true,
	}
	for _, field := range headers {
		if strings.ToLower(field.Name) != field.Name {
			return nil, false, fmt.Errorf("invalid HTTP/2 header %q (lowercase regular names required)", field.Name)
		}
		if field.Name != "connection" {
			continue
		}
		for token := range strings.SplitSeq(field.Value, ",") {
			token = strings.Trim(token, " \t")
			if token == "" { // HTTP list syntax permits empty list elements.
				continue
			}
			if !httpguts.ValidHeaderFieldName(token) {
				return nil, false, fmt.Errorf("invalid Connection option")
			}
			drop[strings.ToLower(token)] = true
		}
	}
	fields := make([]HeaderField, 0, len(headers))
	for _, field := range headers {
		if drop[field.Name] {
			continue
		}
		if field.Name == "te" {
			if !strings.EqualFold(field.Value, "trailers") {
				continue
			}
			field.Value = "trailers"
		}
		fields = append(fields, field)
	}
	return fields, drop["content-length"], nil
}
