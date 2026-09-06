package requestsutls

import (
	"fmt"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// orderHeaders applies a request-local order without modifying either input.
// An empty order preserves the exact header list, including interleaved repeats.
// A name listed once moves all its occurrences together in their original order.
// A name listed repeatedly schedules one occurrence per entry, so its entry count
// must match the number of supplied fields. Absent names are ignored to support
// reusable templates. Unlisted fields follow in their original relative order.
// Names must be lowercase regular header names; pseudo-header order belongs to
// the immutable HTTP/2 profile and cannot be changed through this list.
func orderHeaders(headers []HeaderField, order []string) ([]HeaderField, error) {
	return orderHeadersMatching(headers, order, false)
}

func orderHeadersMatching(headers []HeaderField, order []string, ignoreCase bool) ([]HeaderField, error) {
	if len(order) == 0 {
		return headers, nil
	}
	if ignoreCase {
		order = append([]string(nil), order...)
		for i, name := range order {
			if !httpguts.ValidHeaderFieldName(name) {
				return nil, fmt.Errorf("requests-utls: headers_order[%d]: invalid regular header name %q", i, name)
			}
			order[i] = strings.ToLower(name)
		}
	}
	counts := make(map[string]int, len(order))
	for index, name := range order {
		if !httpguts.ValidHeaderFieldName(name) || strings.ToLower(name) != name {
			return nil, fmt.Errorf("requests-utls: headers_order[%d]: invalid header name %q (lowercase regular names required)", index, name)
		}
		counts[name]++
	}
	groups := make(map[string][]HeaderField, len(counts))
	for _, field := range headers {
		name := field.Name
		if ignoreCase {
			name = strings.ToLower(name)
		}
		if counts[name] != 0 {
			groups[name] = append(groups[name], field)
		}
	}
	for _, name := range order {
		if count, supplied := counts[name], len(groups[name]); count > 1 && supplied > 0 && count != supplied {
			return nil, fmt.Errorf("requests-utls: headers_order: header %q occurs %d times in order but %d times in headers (list once to group all values, or list every occurrence)", name, count, supplied)
		}
	}
	result := make([]HeaderField, 0, len(headers))
	for _, name := range order {
		group := groups[name]
		if len(group) == 0 {
			continue
		}
		if counts[name] == 1 {
			result = append(result, group...)
		} else {
			result = append(result, group[0])
			groups[name] = group[1:]
		}
	}
	for _, field := range headers {
		name := field.Name
		if ignoreCase {
			name = strings.ToLower(name)
		}
		if counts[name] == 0 {
			result = append(result, field)
		}
	}
	return result, nil
}
