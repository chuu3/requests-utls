package http2

import (
	"errors"
	"io"
	"sync"
	"time"
)

// ErrConnectionExpired reports a fresh connection that aged out before use.
var ErrConnectionExpired = errors.New("requests-utls: connection expired before request reservation")

// Called under the same mutex as reservations and stream creation. Reserved
// requests still count as owners, including during cancellation cleanup.
func (cc *ClientConn) retireIfExpiredLocked() bool {
	if !cc.retireAt.IsZero() && !time.Now().Before(cc.retireAt) {
		cc.retiring = true
	}
	if cc.retiring && !cc.closed && cc.streamsReserved == 0 && len(cc.streams) == 0 && cc.lifetimeUses == 0 {
		cc.closed = true
		cc.closedOnIdle = true
		// closeConn can wake the reader which takes mu. Never wait for it here.
		go cc.closeConn()
	}
	return cc.retiring
}

func (cc *ClientConn) releaseLifetimeUse() {
	cc.mu.Lock()
	cc.lifetimeUses--
	cc.resumeIdleCleanupLocked()
	cc.mu.Unlock()
}

// Recheck after either a body owner or a canceled reservation is released.
func (cc *ClientConn) resumeIdleCleanupLocked() {
	cc.retireIfExpiredLocked()
	if !cc.closed && cc.lifetimeUses == 0 && cc.streamsReserved == 0 && len(cc.streams) == 0 && cc.idleTimer != nil && !cc.lastIdle.IsZero() {
		// The idle timer may have fired while a buffered response body was
		// still owned. Restore cleanup using the original idle deadline, so
		// releasing a body does not grant an extra idle timeout interval.
		cc.idleTimer.Reset(max(0, time.Until(cc.lastIdle.Add(cc.idleTimeout))))
	}
}

type lifetimeBody struct {
	io.ReadCloser
	cc   *ClientConn
	once sync.Once
}

func (b *lifetimeBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.once.Do(b.cc.releaseLifetimeUse)
	}
	return n, err
}
func (b *lifetimeBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.cc.releaseLifetimeUse)
	return err
}
