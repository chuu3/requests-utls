package requestsutls

import "strings"

// orderFinalHTTP1Headers includes generated fields in normal ordering, then
// places Host first unless the request explicitly chooses its position.
// Its result never aliases the caller's field slice.
func orderFinalHTTP1Headers(headers []HeaderField, order []string) ([]HeaderField, error) {
	ordered, err := orderHTTP1Headers(append([]HeaderField(nil), headers...), order)
	if err != nil {
		return nil, err
	}
	for _, name := range order {
		if strings.EqualFold(name, "host") {
			return ordered, nil
		}
	}
	for i, field := range ordered {
		if strings.EqualFold(field.Name, "host") {
			copy(ordered[1:i+1], ordered[:i])
			ordered[0] = field
			break
		}
	}
	return ordered, nil
}

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
