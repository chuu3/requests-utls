package requestsutls

import (
	"context"
	"errors"
	"net"
	"net/http/httptrace"
	"sync"
	"time"
)

// StageError identifies the operation that failed. Unwrap preserves cancellation,
// deadline and size-limit classification. The underlying error remains inspectable.
type StageError struct {
	Stage   string
	Elapsed time.Duration
	Err     error
}

func (e *StageError) Error() string {
	kind := "failed"
	if errors.Is(e.Err, context.DeadlineExceeded) {
		kind = "timed out"
	}
	if errors.Is(e.Err, context.Canceled) {
		kind = "canceled"
	}
	return "requests-utls: " + e.Stage + " " + kind + ": " + e.Err.Error()
}
func (e *StageError) Unwrap() error { return e.Err }
func normalizeTimeout(err error) error {
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return context.DeadlineExceeded
	}
	return err
}
func stageError(ctx context.Context, stage string, start time.Time, err error) error {
	if err == nil {
		return nil
	}
	var existing *StageError
	if errors.As(err, &existing) {
		return err
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	} else {
		err = normalizeTimeout(err)
	}
	return &StageError{Stage: stage, Elapsed: time.Since(start), Err: err}
}
func phaseContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout > 0 {
		return context.WithTimeout(ctx, timeout)
	}
	return context.WithCancel(ctx)
}
func readDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline, _ := ctx.Deadline()
	if timeout > 0 {
		phase := time.Now().Add(timeout)
		if deadline.IsZero() || phase.Before(deadline) {
			deadline = phase
		}
	}
	return deadline
}
func (s *Session) dialNetwork(ctx context.Context, network, addr string) (net.Conn, error) {
	if s.proxyURL != nil {
		return dialHTTPConnectTimeouts(ctx, network, addr, s.proxyURL, s.connectTimeout, s.proxyConnectTimeout)
	}
	start := time.Now()
	dialCtx, cancel := phaseContext(ctx, s.connectTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, network, addr)
	return conn, stageError(dialCtx, "connect", start, err)
}

// h2StageTrace measures only phases observed by httptrace. A pooled/shared dial
// can fail before a connection is assigned; that interval is "request", not TLS.
type h2StageTrace struct {
	mu    sync.Mutex
	stage string
	start time.Time
}

func newH2StageTrace(ctx context.Context) (context.Context, *h2StageTrace) {
	state := &h2StageTrace{stage: "request", start: time.Now()}
	set := func(stage string) { state.mu.Lock(); state.stage = stage; state.start = time.Now(); state.mu.Unlock() }
	trace := &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { set("write") },
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				set("response_headers")
			}
		},
	}
	return httptrace.WithClientTrace(ctx, trace), state
}
func (s *h2StageTrace) wrap(ctx context.Context, err error) error {
	s.mu.Lock()
	stage, start := s.stage, s.start
	s.mu.Unlock()
	return stageError(ctx, stage, start, err)
}
