package requestsutls

import "strings"

// coalesceHTTP1Cookies runs only after ordering and final H1 selection. Cookie
// occurrences share one field on H1, while ordinary repeated fields stay intact.
// The first ordered occurrence supplies the field's spelling and position.
func coalesceHTTP1Cookies(headers []HeaderField) []HeaderField {
	first := -1
	var values []string
	out := make([]HeaderField, 0, len(headers))
	for _, field := range headers {
		if !strings.EqualFold(field.Name, "cookie") {
			out = append(out, field)
			continue
		}
		if first == -1 {
			first = len(out)
			out = append(out, field)
		}
		if field.Value != "" {
			values = append(values, field.Value)
		}
	}
	if first != -1 {
		out[first].Value = strings.Join(values, "; ")
	}
	return out
}
