package http2

import (
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func lifetimeTestConn(t *testing.T) (*ClientConn, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	cc := &ClientConn{t: &Transport{}, tconn: client, streams: map[uint32]*clientStream{}, nextStreamID: 1, maxConcurrentStreams: 100, retireAt: time.Now().Add(time.Hour)}
	cc.cond = sync.NewCond(&cc.mu)
	return cc, server
}

func TestLifetimeReservationBoundary(t *testing.T) {
	cc, peer := lifetimeTestConn(t)
	if !cc.ReserveNewRequest() {
		t.Fatal("initial reservation failed")
	}
	cc.mu.Lock()
	cc.retireAt = time.Now().Add(-time.Second)
	cc.mu.Unlock()
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if cc.ReserveNewRequest() {
				t.Error("reservation admitted after deadline")
			}
		})
	}
	wg.Wait()
	cc.mu.Lock()
	if cc.closed || !cc.retiring || cc.streamsReserved != 1 {
		t.Fatalf("reserved owner lost: %+v", cc)
	}
	// A reservation blocked behind request headers must check again before stream creation.
	cc.lifetimeUses = 1
	cc.decrStreamReservationsLocked()
	if err := cc.awaitOpenSlotForStreamLocked(&clientStream{}); err != errClientConnUnusable {
		t.Fatalf("final stream reservation: %v", err)
	}
	cc.mu.Unlock()
	cc.releaseLifetimeUse()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("old socket not closed: %v", err)
	}
}

func TestLifetimeBufferedBodyRemainsOwned(t *testing.T) {
	cc, peer := lifetimeTestConn(t)
	cc.retireAt = time.Now().Add(-time.Second)
	cc.lifetimeUses = 1
	// Simulate END_STREAM already consumed by the read loop, with body bytes
	// still buffered for the application. Stream count alone is insufficient.
	body := &lifetimeBody{ReadCloser: io.NopCloser(strings.NewReader("remaining body")), cc: cc}
	if cc.ReserveNewRequest() {
		t.Fatal("expired socket reused")
	}
	cc.mu.Lock()
	closed := cc.closed
	cc.mu.Unlock()
	if closed {
		t.Fatal("closed while body remains owned")
	}
	data, err := io.ReadAll(body)
	if err != nil || string(data) != "remaining body" {
		t.Fatalf("body=%q err=%v", data, err)
	}
	body.Close()
	body.Close()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal(err)
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.lifetimeUses != 0 {
		t.Fatal("body release not idempotent")
	}
}

func TestLifetimeWakesStreamQuotaWaiter(t *testing.T) {
	cc, _ := lifetimeTestConn(t)
	cc.retireAt = time.Now().Add(30 * time.Millisecond)
	cc.maxConcurrentStreams = 0
	cc.strictMaxConcurrentStreams = true
	cc.lifetimeUses = 1
	done := make(chan error, 1)
	go func() {
		cc.mu.Lock()
		err := cc.awaitOpenSlotForStreamLocked(&clientStream{abort: make(chan struct{})})
		cc.mu.Unlock()
		done <- err
	}()
	select {
	case err := <-done:
		if err != errClientConnUnusable {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("retirement did not wake stream quota waiter")
	}
	cc.releaseLifetimeUse()
}
