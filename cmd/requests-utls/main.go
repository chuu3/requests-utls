// Command requests-utls validates profiles and exercises the Go prototype.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	requests "github.com/chuu3/requests-utls"
	"github.com/chuu3/requests-utls/profile"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: requests-utls validate|import-peet|request [flags]")
	}
	switch args[0] {
	case "validate":
		fs := flag.NewFlagSet("validate", flag.ContinueOnError)
		path := fs.String("profile", "profiles/chrome_152.json", "native profile JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		p, err := profile.LoadFile(*path)
		if err != nil {
			return err
		}
		s, err := requests.NewSession(requests.Options{Profile: p})
		if err != nil {
			return err
		}
		defer s.Close()
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"valid": true, "profile_hash": p.Hash(), "limitations": p.Limitations()})
	case "import-peet":
		fs := flag.NewFlagSet("import-peet", flag.ContinueOnError)
		input := fs.String("in", "", "tls.peet.ws capture JSON")
		output := fs.String("out", "", "native profile destination (stdout if empty)")
		opaque := fs.Bool("allow-opaque", false, "explicitly allow advertisement-only unsupported features")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *input == "" {
			return errors.New("-in is required")
		}
		data, err := os.ReadFile(*input)
		if err != nil {
			return err
		}
		p, err := profile.ImportPeet(data, *opaque)
		if err != nil {
			return err
		}
		for _, limitation := range p.Limitations() {
			fmt.Fprintln(os.Stderr, "limitation:", limitation)
		}
		data, err = json.MarshalIndent(p, "", "  ")
		if err != nil {
			return err
		}
		data = append(data, '\n')
		if *output != "" {
			return os.WriteFile(*output, data, 0644)
		}
		_, err = os.Stdout.Write(data)
		return err
	case "request":
		return runRequests(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

type headerFlags []requests.HeaderField

func (h *headerFlags) String() string { return fmt.Sprint([]requests.HeaderField(*h)) }
func (h *headerFlags) Set(s string) error {
	name, value, ok := strings.Cut(s, ":")
	if !ok || name == "" {
		return errors.New("header must be name:value")
	}
	*h = append(*h, requests.HeaderField{Name: strings.TrimSpace(name), Value: strings.TrimLeft(value, " \t")})
	return nil
}

func runRequests(args []string) error {
	fs := flag.NewFlagSet("request", flag.ContinueOnError)
	path := fs.String("profile", "profiles/chrome_152.json", "native profile JSON")
	url := fs.String("url", "", "HTTP or HTTPS URL")
	method := fs.String("method", "GET", "HTTP method")
	body := fs.String("data", "", "request body")
	n := fs.Int("n", 1, "number of requests")
	c := fs.Int("c", 1, "concurrent workers sharing one Session")
	timeout := fs.Duration("timeout", 20*time.Second, "timeout for each request")
	insecure := fs.Bool("insecure", false, "disable certificate validation (local diagnostics only)")
	forceHTTP1 := fs.Bool("force-http1", false, "advertise and use only HTTP/1.1")
	randomJA3 := fs.Bool("random-ja3", false, "shuffle eligible extensions for each new connection")
	rawContent := fs.Bool("raw-content", false, "return compressed response bytes without content decoding")
	proxyURL := fs.String("proxy", "", "explicit HTTP CONNECT proxy URL (no implicit environment proxy)")
	proxyEnv := fs.String("proxy-env", "", "read the explicit proxy URL from this environment variable")
	retries := fs.Int("unprocessed-retries", 0, "proven-unprocessed retry limit: 0 means3, -1 disables, maximum32")
	headerOrder := fs.String("headers-order", "", "request-level comma-separated regular header names; duplicates allowed")
	var headers headerFlags
	fs.Var(&headers, "H", "ordered header; may repeat")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *proxyEnv != "" {
		if *proxyURL != "" {
			return errors.New("use either -proxy or -proxy-env")
		}
		*proxyURL = os.Getenv(*proxyEnv)
		if *proxyURL == "" {
			return errors.New("proxy environment variable is empty")
		}
	}
	if *url == "" || *n < 1 || *c < 1 || *timeout <= 0 {
		return errors.New("-url required; -n, -c, and -timeout must be positive")
	}
	if *c > *n {
		*c = *n
	}
	var order []string
	if *headerOrder != "" {
		order = strings.Split(*headerOrder, ",")
	}
	p, err := profile.LoadFile(*path)
	if err != nil {
		return err
	}
	for _, limitation := range p.Limitations() {
		fmt.Fprintln(os.Stderr, "limitation:", limitation)
	}
	s, err := requests.NewSession(requests.Options{Profile: p, ProxyURL: *proxyURL, InsecureSkipVerify: *insecure, MaxConcurrentRequests: *c, MaxUnprocessedRetries: *retries, ForceHTTP1: *forceHTTP1, RandomJA3: *randomJA3, DisableContentDecoding: *rawContent})
	if err != nil {
		return err
	}
	defer s.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	jobs := make(chan int)
	var wg sync.WaitGroup
	var outputMu sync.Mutex
	failed := 0
	enc := json.NewEncoder(os.Stdout)
	for range *c {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				requestCtx, cancel := context.WithTimeout(ctx, *timeout)
				start := time.Now()
				res, err := s.Do(requestCtx, requests.Request{Method: *method, URL: *url, Headers: headers, HeadersOrder: order, Body: []byte(*body)})
				cancel()
				result := map[string]any{"id": id, "elapsed_ms": time.Since(start).Milliseconds()}
				if err != nil {
					result["error"] = err.Error()
				} else {
					result["response"] = res
				}
				outputMu.Lock()
				if err != nil {
					failed++
				}
				if err := enc.Encode(result); err != nil {
					failed++
				}
				outputMu.Unlock()
			}
		}()
	}
	for id := 0; id < *n; id++ {
		if ctx.Err() != nil {
			break
		}
		jobs <- id
	}
	close(jobs)
	wg.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if failed > 0 {
		return fmt.Errorf("%d request/output failures", failed)
	}
	return nil
}
