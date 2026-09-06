// Package native implements the handle and completion lifecycle behind ABI v1.
// It contains no cgo and is exercised by the Go race detector.
package native

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	requestsutls "github.com/chuu3/requests-utls"
	"github.com/chuu3/requests-utls/profile"
)

const ABIVersion = 1

// Codes are stable across ABI v1 releases.
const (
	OK int32 = iota
	PollTimeout
	SessionClosed
	InvalidInput
	InvalidHandle
	QueueFull
	Canceled
	Deadline
	ResponseTooLarge
	TransportError
	InternalError
)

const (
	MaxMetadataBytes = 4 << 20
	MaxRequestBytes  = 64 << 20
)

type Result struct {
	Code   int32
	Handle uint64
	Data   []byte
}

func Error(code int32, message string) Result {
	data, _ := json.Marshal(struct {
		Message string `json:"message"`
	}{message})
	return Result{Code: code, Data: data}
}

type sessionConfig struct {
	Profile                  json.RawMessage `json:"profile"`
	ProxyURL                 string          `json:"proxy_url"`
	ProxyAuth                *proxyAuth      `json:"proxy_auth"`
	CAPEM                    string          `json:"ca_pem"`
	InsecureSkipVerify       bool            `json:"insecure_skip_verify"`
	DisableSessionResumption bool            `json:"disable_session_resumption"`
	MaxConcurrentRequests    int             `json:"max_concurrent_requests"`
	MaxPendingRequests       int             `json:"max_pending_requests"`
	MaxResponseBytes         int64           `json:"max_response_bytes"`
	MaxUnprocessedRetries    int             `json:"max_unprocessed_retries"`
}

type proxyAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type requestMetadata struct {
	Method       string                     `json:"method"`
	URL          string                     `json:"url"`
	Headers      []requestsutls.HeaderField `json:"headers"`
	HeadersOrder []string                   `json:"headers_order"`
	TimeoutMS    int64                      `json:"timeout_ms"`
}

type responseMetadata struct {
	StatusCode int                        `json:"status_code"`
	Headers    []requestsutls.HeaderField `json:"headers"`
	Protocol   string                     `json:"protocol"`
	BodySize   int                        `json:"body_size"`
}

type session struct {
	engine    *requestsutls.Session
	limit     int
	requests  map[uint64]*request
	queue     []*request
	changed   chan struct{}
	closed    bool
	closeDone chan struct{}
	wg        sync.WaitGroup
}

type request struct {
	id       uint64
	session  *session
	cancel   context.CancelFunc
	done     bool
	released bool
	queued   bool
	result   Result
	body     []byte
}

// Registry protects only handle/queue state. Network calls and waits never hold
// its mutex. IDs are monotonically increasing and are never reused.
type Registry struct {
	mu       sync.Mutex
	next     uint64
	sessions map[uint64]*session
	requests map[uint64]*request
}

func NewRegistry() *Registry {
	return &Registry{sessions: make(map[uint64]*session), requests: make(map[uint64]*request)}
}

func strictJSON(data []byte, target any) error {
	if len(data) == 0 || len(data) > MaxMetadataBytes {
		return fmt.Errorf("JSON input must contain 1..%d bytes", MaxMetadataBytes)
	}
	if data = bytes.TrimSpace(data); len(data) == 0 || data[0] != '{' {
		return errors.New("JSON input must be an object")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON content")
	}
	return nil
}

func (r *Registry) nextIDLocked() (uint64, bool) {
	if r.next == ^uint64(0) {
		return 0, false
	}
	r.next++
	return r.next, true
}

func (r *Registry) SessionCreate(data []byte) Result {
	var config sessionConfig
	if err := strictJSON(data, &config); err != nil {
		return Error(InvalidInput, err.Error())
	}
	p, err := profile.Load(config.Profile)
	if err != nil {
		return Error(InvalidInput, err.Error())
	}
	options := requestsutls.Options{
		Profile: p, ProxyURL: config.ProxyURL, InsecureSkipVerify: config.InsecureSkipVerify,
		DisableSessionResumption: config.DisableSessionResumption,
		MaxConcurrentRequests:    config.MaxConcurrentRequests, MaxPendingRequests: config.MaxPendingRequests,
		MaxResponseBytes: config.MaxResponseBytes, MaxUnprocessedRetries: config.MaxUnprocessedRetries,
	}
	if config.ProxyAuth != nil {
		options.ProxyAuth = &requestsutls.ProxyAuth{Username: config.ProxyAuth.Username, Password: config.ProxyAuth.Password}
	}
	if config.CAPEM != "" {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(config.CAPEM)) {
			return Error(InvalidInput, "ca_pem contains no valid certificates")
		}
		options.RootCAs = roots
	}
	engine, err := requestsutls.NewSession(options)
	if err != nil {
		return Error(InvalidInput, err.Error())
	}
	limit := config.MaxConcurrentRequests
	if limit == 0 {
		limit = 64
	}
	s := &session{
		engine: engine, limit: limit + config.MaxPendingRequests,
		requests: make(map[uint64]*request), changed: make(chan struct{}), closeDone: make(chan struct{}),
	}
	limitations := p.Limitations()
	if limitations == nil {
		limitations = []string{}
	}
	metadata, _ := json.Marshal(struct {
		ProfileHash string   `json:"profile_hash"`
		Limitations []string `json:"limitations"`
	}{p.Hash(), limitations})
	r.mu.Lock()
	id, ok := r.nextIDLocked()
	if ok {
		r.sessions[id] = s
	}
	r.mu.Unlock()
	if !ok {
		engine.Close()
		return Error(InternalError, "handle space exhausted")
	}
	return Result{Handle: id, Data: metadata}
}

// RequestSubmit owns all input before returning. Every accepted request produces
// exactly one completion unless released or its Session is closed.
func (r *Registry) RequestSubmit(sessionID uint64, metadata, body []byte) Result {
	var meta requestMetadata
	if err := strictJSON(metadata, &meta); err != nil {
		return Error(InvalidInput, err.Error())
	}
	if meta.TimeoutMS < 0 || meta.TimeoutMS > int64((1<<63-1)/time.Millisecond) {
		return Error(InvalidInput, "timeout_ms must be nonnegative and fit a Go duration")
	}
	if len(body) > MaxRequestBytes {
		return Error(InvalidInput, "request body exceeds 64 MiB ABI limit")
	}
	if meta.URL == "" {
		return Error(InvalidInput, "url is required")
	}
	in := requestsutls.Request{Method: meta.Method, URL: meta.URL, Headers: meta.Headers, HeadersOrder: meta.HeadersOrder, Body: bytes.Clone(body)}
	var ctx context.Context
	var cancel context.CancelFunc
	if meta.TimeoutMS > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(meta.TimeoutMS)*time.Millisecond)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	r.mu.Lock()
	s := r.sessions[sessionID]
	if s == nil || s.closed {
		r.mu.Unlock()
		cancel()
		if s != nil {
			return Error(SessionClosed, "session is closed")
		}
		return Error(InvalidHandle, "unknown session handle")
	}
	if len(s.requests) >= s.limit {
		r.mu.Unlock()
		cancel()
		return Error(QueueFull, "outstanding request limit reached; release completed requests")
	}
	id, ok := r.nextIDLocked()
	if !ok {
		r.mu.Unlock()
		cancel()
		return Error(InternalError, "handle space exhausted")
	}
	q := &request{id: id, session: s, cancel: cancel}
	s.requests[id], r.requests[id] = q, q
	s.wg.Add(1)
	r.mu.Unlock()
	go r.execute(ctx, q, in)
	return Result{Handle: id}
}

func (r *Registry) execute(ctx context.Context, q *request, in requestsutls.Request) {
	defer q.session.wg.Done()
	defer q.cancel()
	result, body := execute(q.session.engine, ctx, in)
	result.Handle = q.id
	r.mu.Lock()
	defer r.mu.Unlock()
	q.done = true
	if q.released || q.session.closed {
		delete(q.session.requests, q.id)
		return
	}
	q.result, q.body, q.queued = result, body, true
	q.session.queue = append(q.session.queue, q)
	notifyLocked(q.session)
}

func execute(engine *requestsutls.Session, ctx context.Context, in requestsutls.Request) (result Result, body []byte) {
	defer func() {
		if recover() != nil {
			result, body = Error(InternalError, "internal request panic"), nil
		}
	}()
	response, err := engine.Do(ctx, in)
	if err != nil {
		code := int32(TransportError)
		switch {
		case errors.Is(err, requestsutls.ErrInvalidRequest):
			code = InvalidInput
		case errors.Is(err, context.Canceled):
			code = Canceled
		case errors.Is(err, context.DeadlineExceeded):
			code = Deadline
		case errors.Is(err, requestsutls.ErrSessionClosed):
			code = SessionClosed
		case errors.Is(err, requestsutls.ErrQueueFull):
			code = QueueFull
		case errors.Is(err, requestsutls.ErrResponseTooLarge):
			code = ResponseTooLarge
		}
		return Error(code, err.Error()), nil
	}
	metadata, err := json.Marshal(responseMetadata{response.StatusCode, response.Headers, response.Protocol, len(response.Body)})
	if err != nil {
		return Error(InternalError, "response metadata encoding failed"), nil
	}
	return Result{Data: metadata}, response.Body
}

func notifyLocked(s *session) {
	close(s.changed)
	s.changed = make(chan struct{})
}

// SessionPoll consumes one completion, retaining its body until RequestRelease.
// timeoutMS == -1 waits indefinitely, 0 checks immediately, positive values wait
// at most that many milliseconds. Multiple pollers are safe; each event goes to one.
func (r *Registry) SessionPoll(sessionID uint64, timeoutMS int32) Result {
	if timeoutMS < -1 {
		return Error(InvalidInput, "poll timeout must be -1 or nonnegative")
	}
	r.mu.Lock()
	s := r.sessions[sessionID]
	r.mu.Unlock()
	if s == nil {
		return Error(InvalidHandle, "unknown session handle")
	}
	var timer *time.Timer
	var timerC <-chan time.Time
	if timeoutMS > 0 {
		timer = time.NewTimer(time.Duration(timeoutMS) * time.Millisecond)
		defer timer.Stop()
		timerC = timer.C
	}
	for {
		r.mu.Lock()
		if s.closed {
			r.mu.Unlock()
			return Error(SessionClosed, "session is closed")
		}
		if len(s.queue) > 0 {
			q := s.queue[0]
			s.queue[0] = nil
			s.queue = s.queue[1:]
			q.queued = false
			result := q.result
			r.mu.Unlock()
			result.Data = bytes.Clone(result.Data)
			return result
		}
		changed := s.changed
		r.mu.Unlock()
		if timeoutMS == 0 {
			return Result{Code: PollTimeout}
		}
		select {
		case <-changed:
		case <-timerC:
			return Result{Code: PollTimeout}
		}
	}
}

func (r *Registry) RequestBody(requestID uint64) Result {
	r.mu.Lock()
	q := r.requests[requestID]
	if q == nil {
		r.mu.Unlock()
		return Error(InvalidHandle, "unknown request handle")
	}
	if !q.done {
		r.mu.Unlock()
		return Error(InvalidInput, "request has not completed")
	}
	result := q.result
	if result.Code == OK {
		result.Data = q.body
	}
	r.mu.Unlock()
	result.Data = bytes.Clone(result.Data)
	return result
}

func (r *Registry) RequestCancel(requestID uint64) int32 {
	r.mu.Lock()
	q := r.requests[requestID]
	if q == nil {
		r.mu.Unlock()
		return InvalidHandle
	}
	cancel := q.cancel
	r.mu.Unlock()
	cancel()
	return OK
}

// RequestRelease is idempotent. Releasing pending work cancels it and suppresses
// its completion; its admission slot remains reserved until the goroutine exits.
func (r *Registry) RequestRelease(requestID uint64) int32 {
	r.mu.Lock()
	q := r.requests[requestID]
	if q == nil {
		r.mu.Unlock()
		return OK
	}
	delete(r.requests, requestID)
	q.released = true
	q.body, q.result.Data = nil, nil
	if q.queued {
		for i, queued := range q.session.queue {
			if queued == q {
				copy(q.session.queue[i:], q.session.queue[i+1:])
				q.session.queue[len(q.session.queue)-1] = nil
				q.session.queue = q.session.queue[:len(q.session.queue)-1]
				break
			}
		}
		q.queued = false
	}
	if q.done {
		delete(q.session.requests, requestID)
	}
	cancel := q.cancel
	r.mu.Unlock()
	cancel()
	return OK
}

// SessionClose cancels all work, wakes pollers, waits for execution, and clears
// all owned handles. Repeated/concurrent close is safe, including unknown IDs.
func (r *Registry) SessionClose(sessionID uint64) int32 {
	r.mu.Lock()
	s := r.sessions[sessionID]
	if s == nil {
		r.mu.Unlock()
		return OK
	}
	if s.closed {
		r.mu.Unlock()
		<-s.closeDone
		return OK
	}
	s.closed = true
	for id, q := range s.requests {
		delete(r.requests, id)
		q.released = true
		q.body, q.result.Data = nil, nil
		q.cancel()
	}
	s.queue = nil
	notifyLocked(s)
	r.mu.Unlock()
	s.engine.Close()
	s.wg.Wait()
	r.mu.Lock()
	s.requests = nil
	delete(r.sessions, sessionID)
	close(s.closeDone)
	r.mu.Unlock()
	return OK
}

// ProfileImport converts a Peet capture into the native schema; opaque payloads
// are permitted only when explicitly requested, subject to profile validation.
func ProfileImport(data []byte, allowOpaque bool) Result {
	if len(data) == 0 || len(data) > MaxMetadataBytes {
		return Error(InvalidInput, "profile capture exceeds JSON input limits")
	}
	p, err := profile.ImportPeet(data, allowOpaque)
	if err != nil {
		return Error(InvalidInput, err.Error())
	}
	data, err = p.MarshalJSON()
	if err != nil {
		return Error(InternalError, "profile encoding failed")
	}
	return Result{Data: data}
}
