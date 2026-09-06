// Command peetcheck performs an opt-in live acceptance probe. It is not part of
// go test and never emits the service's client IP or raw connection identifiers.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	requests "github.com/chuu3/requests-utls"
	"github.com/chuu3/requests-utls/profile"
)

type reference struct {
	JA3           string `json:"ja3"`
	JA3Hash       string `json:"ja3_hash"`
	JA4           string `json:"ja4"`
	PeetprintHash string `json:"peetprint_hash"`
	Akamai        string `json:"akamai_fingerprint"`
}
type result struct {
	ID          int             `json:"id"`
	ElapsedMS   int64           `json:"elapsed_ms"`
	Status      int             `json:"status"`
	Protocol    string          `json:"protocol,omitempty"`
	Fingerprint reference       `json:"fingerprint"`
	Checks      map[string]bool `json:"checks"`
	Error       string          `json:"error,omitempty"`
}
type capture struct {
	HTTPVersion string `json:"http_version"`
	TLS         struct {
		JA3           string `json:"ja3"`
		JA3Hash       string `json:"ja3_hash"`
		JA4           string `json:"ja4"`
		PeetprintHash string `json:"peetprint_hash"`
		Extensions    []struct {
			Name string `json:"name"`
			Data string `json:"data"`
		} `json:"extensions"`
	} `json:"tls"`
	HTTP2 struct {
		Akamai string `json:"akamai_fingerprint"`
		Frames []struct {
			Type    string   `json:"frame_type"`
			Headers []string `json:"headers"`
		} `json:"sent_frames"`
	} `json:"http2"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	path := flag.String("profile", "profiles/chrome_152.json", "native profile")
	refPath := flag.String("reference", "testdata/chrome_152_fingerprint.json", "sanitized browser baseline")
	proxy := flag.String("proxy", "", "explicit HTTP CONNECT proxy")
	proxyEnv := flag.String("proxy-env", "", "read explicit proxy URL from this environment variable")
	n := flag.Int("n", 8, "total requests")
	c := flag.Int("c", 4, "concurrent workers, one Session")
	retries := flag.Int("unprocessed-retries", 8, "bounded retries only when HTTP/2 proves no processing (test site sends GOAWAY)")
	timeout := flag.Duration("timeout", 30*time.Second, "total timeout per task, including safe retries")
	flag.Parse()
	if *proxyEnv != "" {
		if *proxy != "" {
			return errors.New("use either -proxy or -proxy-env")
		}
		*proxy = os.Getenv(*proxyEnv)
		if *proxy == "" {
			return errors.New("proxy environment variable is empty")
		}
	}
	if *n < 1 || *c < 1 || *timeout <= 0 {
		return errors.New("n, c and timeout must be positive")
	}
	if *c > *n {
		*c = *n
	}
	p, err := profile.LoadFile(*path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*refPath)
	if err != nil {
		return err
	}
	var expected reference
	if err = json.Unmarshal(data, &expected); err != nil {
		return err
	}
	data, err = json.Marshal(p)
	if err != nil {
		return err
	}
	var native struct {
		TLS struct {
			Extensions []struct {
				ID   uint16 `json:"id"`
				Data string `json:"data_hex"`
			} `json:"extensions"`
		} `json:"tls"`
	}
	if err = json.Unmarshal(data, &native); err != nil {
		return err
	}
	payload := ""
	for _, ext := range native.TLS.Extensions {
		if ext.ID == 51764 {
			payload = ext.Data
		}
	}
	if payload == "" {
		return errors.New("probe expects profile with51764 payload")
	}
	// This checker compares every handshake to one cold-connection fingerprint.
	// Resumption is checked separately because a real PSK adds extension 41.
	s, err := requests.NewSession(requests.Options{Profile: p, ProxyURL: *proxy, MaxConcurrentRequests: *c, MaxUnprocessedRetries: *retries, DisableSessionResumption: true})
	if err != nil {
		return err
	}
	defer s.Close()
	jobs := make(chan int)
	results := make(chan result, *n)
	var wg sync.WaitGroup
	for range *c {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				results <- probe(s, id, expected, payload, *timeout)
			}
		}()
	}
	for id := 0; id < *n; id++ {
		jobs <- id
	}
	close(jobs)
	wg.Wait()
	close(results)
	all := make([]result, 0, *n)
	success := 0
	for r := range results {
		all = append(all, r)
		ok := r.Error == ""
		for _, v := range r.Checks {
			ok = ok && v
		}
		if ok {
			success++
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	report := map[string]any{"endpoint": "https://tls.peet.ws/api/all", "recorded_at_utc": time.Now().UTC().Format(time.RFC3339), "profile_hash": p.Hash(), "proxy_used": *proxy != "", "requests": *n, "concurrency": *c, "max_unprocessed_retries": *retries, "timeout_ms": timeout.Milliseconds(), "passed": success, "limitations": p.Limitations(), "results": all}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return err
	}
	if success != *n {
		return fmt.Errorf("%d/%d live probes passed", success, *n)
	}
	return nil
}
func probe(s *requests.Session, id int, expected reference, payload string, timeout time.Duration) (r result) {
	start := time.Now()
	defer func() { r.ElapsedMS = time.Since(start).Milliseconds() }()
	marker := fmt.Sprintf("probe-%d", id)
	fields := []requests.HeaderField{{Name: "user-agent", Value: "requests-utls-prototype"}, {Name: "x-request-id", Value: marker}, {Name: "x-a", Value: marker + "-first"}, {Name: "x-b", Value: marker + "-middle"}, {Name: "x-a", Value: marker + "-last"}, {Name: "cookie", Value: "probe=" + marker}}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	r = result{ID: id, Checks: make(map[string]bool)}
	res, err := s.Do(ctx, requests.Request{Method: "GET", URL: "https://tls.peet.ws/api/all", Headers: fields})
	if err != nil {
		r.Error = err.Error()
		return r
	}
	r.Status = res.StatusCode
	r.Protocol = res.Protocol
	var got capture
	if err = json.Unmarshal(res.Body, &got); err != nil {
		r.Error = err.Error()
		return r
	}
	r.Fingerprint = reference{JA3: got.TLS.JA3, JA3Hash: got.TLS.JA3Hash, JA4: got.TLS.JA4, PeetprintHash: got.TLS.PeetprintHash, Akamai: got.HTTP2.Akamai}
	r.Checks["http_200_h2"] = res.StatusCode == 200 && got.HTTPVersion == "h2"
	r.Checks["ja3"] = got.TLS.JA3 == expected.JA3
	r.Checks["ja3_hash"] = got.TLS.JA3Hash == expected.JA3Hash
	r.Checks["ja4"] = got.TLS.JA4 == expected.JA4
	r.Checks["peetprint_hash"] = got.TLS.PeetprintHash == expected.PeetprintHash
	r.Checks["http2_fingerprint"] = got.HTTP2.Akamai == expected.Akamai
	r.Checks["extension_51764_payload"] = false
	for _, ext := range got.TLS.Extensions {
		if strings.Contains(ext.Name, "51764") || strings.Contains(ext.Name, "trust_anchor") {
			r.Checks["extension_51764_payload"] = strings.EqualFold(ext.Data, payload)
		}
	}
	want := make([]string, 0, len(fields))
	for _, f := range fields {
		want = append(want, f.Name+": "+f.Value)
	}
	r.Checks["ordered_duplicates_and_cookie_isolation"] = false
	for _, frame := range got.HTTP2.Frames {
		if frame.Type != "HEADERS" {
			continue
		}
		var regular []string
		for _, h := range frame.Headers {
			if !strings.HasPrefix(h, ":") {
				regular = append(regular, h)
			}
		}
		if slices.Equal(regular, want) {
			r.Checks["ordered_duplicates_and_cookie_isolation"] = true
		}
	}
	return r
}
