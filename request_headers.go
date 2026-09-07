package requestsutls

import (
	"errors"
	"slices"
	"strconv"
	"strings"
)

// normalizeContentLength owns the returned fields and replaces a caller's
// captured length with the size of this request's final body. Keep the field's
// spelling and position; generation and ordering happen in the protocol path.
func normalizeContentLength(headers []HeaderField, bodyLength int) ([]HeaderField, bool, error) {
	fields := slices.Clone(headers)
	seen := false
	for i, field := range fields {
		if !strings.EqualFold(field.Name, "content-length") {
			continue
		}
		if seen {
			return nil, false, errors.New("content-length must appear at most once")
		}
		seen = true
		fields[i].Value = strconv.Itoa(bodyLength)
	}
	return fields, seen, nil
}

func needsContentLength(method string, bodyLength int) bool {
	return bodyLength != 0 || method == "POST" || method == "PUT" || method == "PATCH"
}
