package requestsutls

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestFinalHTTP1HostOrderCopiesInputs(t *testing.T) {
	for _, test := range []struct {
		name  string
		order []string
		want  []HeaderField
	}{
		{"omitted", nil, []HeaderField{{"hOsT", "custom.example:8443"}, {"X-First", "one"}, {"X-Last", "two"}}},
		{"other_fields_only", []string{"x-last"}, []HeaderField{{"hOsT", "custom.example:8443"}, {"X-Last", "two"}, {"X-First", "one"}}},
		{"explicit_position", []string{"x-last", "HOST"}, []HeaderField{{"X-Last", "two"}, {"hOsT", "custom.example:8443"}, {"X-First", "one"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fields := []HeaderField{{"X-First", "one"}, {"hOsT", "custom.example:8443"}, {"X-Last", "two"}}
			original := append([]HeaderField(nil), fields...)
			originalOrder := append([]string(nil), test.order...)
			got, err := orderFinalHTTP1Headers(fields, test.order)
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("fields=%+v want=%+v err=%v", got, test.want, err)
			}
			got[0].Value = "changed output"
			if !reflect.DeepEqual(fields, original) || !reflect.DeepEqual(test.order, originalOrder) {
				t.Fatal("final Host ordering aliases or mutates caller input")
			}
		})
	}
}

func TestHTTP1HostPlacementOnWire(t *testing.T) {
	for _, protocol := range []string{"http1_plain", "http1_forced", "http1_fallback"} {
		t.Run(protocol, func(t *testing.T) {
			session, endpoint, _ := generatedHeaderPeer(t, protocol, nil)
			connection := 0
			for _, explicitHost := range []bool{false, true} {
				for _, mode := range []string{"no_order", "other_fields", "host_position"} {
					t.Run(fmt.Sprintf("%s/explicit_host=%t", mode, explicitHost), func(t *testing.T) {
						fields := []HeaderField{{"X-First", "one"}, {"cOoKiE", "a=1"}, {"X-Last", "two"}, {"cookie", "b=2"}, {"cOnTeNt-LeNgTh", "incorrect"}}
						host := generatedHeaderHost(t, endpoint)
						if explicitHost {
							host = HeaderField{"hOsT", "custom.example:8443"}
							fields = append(fields, host) // A late supplied Host also moves.
						}
						length, cookie := HeaderField{"cOnTeNt-LeNgTh", "3"}, HeaderField{"cOoKiE", "a=1; b=2"}
						var order []string
						want := []HeaderField{host, fields[0], cookie, fields[2], length}
						switch mode {
						case "other_fields":
							order = []string{"x-last", "Cookie", "CONTENT-LENGTH", "cookie"}
							want = []HeaderField{host, fields[2], cookie, length, fields[0]}
						case "host_position":
							order = []string{"cookie", "cOnTeNt-LeNgTh", "HoSt", "cookie", "x-first"}
							want = []HeaderField{cookie, length, host, fields[0], fields[2]}
						}
						originalFields := append([]HeaderField(nil), fields...)
						originalOrder := append([]string(nil), order...)
						for range 2 {
							response, err := session.Do(testContext(t), Request{Method: "POST", URL: endpoint, Headers: fields, HeadersOrder: order, Body: []byte("界")})
							captured := decodeGeneratedHeaders(t, response, err)
							if !reflect.DeepEqual(captured.Headers, want) || !bytes.Equal(captured.Body, []byte("界")) {
								t.Fatalf("Host placement/casing/value, Cookie merge or body length changed: headers=%+v want=%+v", captured.Headers, want)
							}
							if connection == 0 {
								connection = captured.Connection
							} else if captured.Connection != connection {
								t.Fatalf("Host placement prevented reuse: got=%d want=%d", captured.Connection, connection)
							}
						}
						if !reflect.DeepEqual(fields, originalFields) || !reflect.DeepEqual(order, originalOrder) {
							t.Fatal("Host placement mutated request inputs")
						}
					})
				}
			}
		})
	}
}

func TestHTTP1HostPlacementConcurrentIsolation(t *testing.T) {
	for _, protocol := range []string{"http1_plain", "http1_forced", "http1_fallback"} {
		t.Run(protocol, func(t *testing.T) {
			const workers = 12
			started, release := make(chan struct{}, workers), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			session, endpoint, _ := generatedHeaderPeer(t, protocol, func(ctx context.Context) {
				started <- struct{}{}
				select {
				case <-release:
				case <-ctx.Done():
				}
			})
			orders := [][]string{{"cookie", "x-id", "content-length", "cookie"}, {"x-id", "cookie", "HOST", "content-length", "cookie"}}
			originalOrders := [][]string{append([]string(nil), orders[0]...), append([]string(nil), orders[1]...)}
			results := make(chan error, workers)
			for i := range workers {
				go func() {
					first, last := fmt.Sprintf("a=%d", i), fmt.Sprintf("b=%d", i)
					id := HeaderField{"X-ID", fmt.Sprint(i)}
					host := generatedHeaderHost(t, endpoint)
					fields := []HeaderField{{"Cookie", first}, id, {"cOOkie", last}}
					if i%3 == 0 {
						host = HeaderField{"hOSt", fmt.Sprintf("request-%d.example", i)}
						fields = append(fields, host)
					}
					original := append([]HeaderField(nil), fields...)
					body := []byte(strings.Repeat("界", i+1))
					cookie, length := HeaderField{"Cookie", first + "; " + last}, HeaderField{"Content-Length", fmt.Sprint(len(body))}
					want := []HeaderField{host, cookie, id, length}
					if i%2 != 0 {
						want = []HeaderField{id, cookie, host, length}
					}
					response, err := session.Do(testContext(t), Request{Method: "POST", URL: endpoint, Headers: fields, HeadersOrder: orders[i%2], Body: body})
					if err == nil {
						var captured generatedHeaderObservation
						err = json.Unmarshal(response.Body, &captured)
						if err == nil && (!reflect.DeepEqual(captured.Headers, want) || !bytes.Equal(captured.Body, body) || !reflect.DeepEqual(fields, original)) {
							err = fmt.Errorf("request %d Host/cookie/order/body or caller snapshot changed", i)
						}
					}
					results <- err
				}()
			}
			for range workers {
				await(t, started)
			}
			once.Do(func() { close(release) })
			for range workers {
				if err := <-results; err != nil {
					t.Error(err)
				}
			}
			if !reflect.DeepEqual(orders, originalOrders) {
				t.Fatal("concurrent requests modified a shared Host order template")
			}
		})
	}
}
