package requestsutls

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestHTTP1CookieCoalescingAfterOrderingAndALPN(t *testing.T) {
	for _, protocol := range []string{"http1_plain", "http1_forced", "http1_fallback", "http2", "http2_from_h1"} {
		t.Run(protocol, func(t *testing.T) {
			session, endpoint, _ := generatedHeaderPeer(t, protocol, nil)
			connection := 0
			for _, test := range []struct {
				name   string
				values [3]string
				merged string
			}{
				{"nonempty", [3]string{"a=1", "b=2", "c=3"}, "a=1; b=2; c=3"},
				{"first_empty", [3]string{"", "b=2", "c=3"}, "b=2; c=3"},
				{"middle_empty", [3]string{"a=1", "", "c=3"}, "a=1; c=3"},
				{"all_empty", [3]string{"", "", ""}, ""},
			} {
				for _, explicitLength := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/explicit_length=%t", test.name, explicitLength), func(t *testing.T) {
						fields := []HeaderField{{"X-Dupe", "first"}, {"cOoKiE", test.values[0]}, {"x-DUPE", "second"}, {"cookie", test.values[1]}, {"X-Tail", "middle"}, {"COOKIE", test.values[2]}}
						length := HeaderField{"Content-Length", "3"}
						if explicitLength {
							length.Name = "cOnTeNt-LeNgTh"
							fields = append(fields, HeaderField{length.Name, "incorrect"})
						}
						// Count original occurrences before joining Cookie. The length
						// field is deliberately placed between Cookie occurrences.
						order := []string{"x-dupe", "cookie", "Content-Length", "x-tail", "COOKIE", "x-dupe", "cookie", "host"}
						originalFields := append([]HeaderField(nil), fields...)
						originalOrder := append([]string(nil), order...)
						var expected []HeaderField
						if strings.HasPrefix(protocol, "http2") {
							expected = []HeaderField{fields[0], fields[1], length, fields[4], fields[3], fields[2], fields[5]}
							expected = generatedHeadersOnWire("http2", expected)
						} else {
							expected = []HeaderField{fields[0], {"cOoKiE", test.merged}, length, fields[4], fields[2], generatedHeaderHost(t, endpoint)}
						}
						for range 2 {
							response, err := session.Do(testContext(t), Request{Method: "POST", URL: endpoint, Headers: fields, HeadersOrder: order, Body: []byte("界")})
							captured := decodeGeneratedHeaders(t, response, err)
							if !reflect.DeepEqual(captured.Headers, expected) || !bytes.Equal(captured.Body, []byte("界")) {
								t.Fatalf("wire fields = %+v, want %+v; body length=%d", captured.Headers, expected, len(captured.Body))
							}
							if connection == 0 {
								connection = captured.Connection
							} else if captured.Connection != connection {
								t.Fatalf("Cookie normalization prevented connection reuse: got=%d want=%d", captured.Connection, connection)
							}
						}
						if !reflect.DeepEqual(fields, originalFields) || !reflect.DeepEqual(order, originalOrder) {
							t.Fatal("Cookie normalization mutated caller-owned fields or order")
						}
					})
				}
			}
		})
	}
}
