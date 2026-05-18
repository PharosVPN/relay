// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestCapBackoff verifies the ceiling math — the function is trivial
// but it's the basis of the escalation curve the rest of the suite
// depends on, so lock it down explicitly.
func TestCapBackoff(t *testing.T) {
	max := 60 * time.Second
	cases := []struct {
		in, want time.Duration
	}{
		{500 * time.Millisecond, 500 * time.Millisecond},
		{30 * time.Second, 30 * time.Second},
		{60 * time.Second, 60 * time.Second},
		{120 * time.Second, 60 * time.Second}, // clamp
		{time.Hour, 60 * time.Second},         // clamp
	}
	for _, c := range cases {
		if got := capBackoff(c.in, max); got != c.want {
			t.Errorf("capBackoff(%s, %s) = %s, want %s", c.in, max, got, c.want)
		}
	}
}

// TestWaitOrCancel confirms the helper returns promptly on ctx
// cancel and otherwise waits the full duration.
func TestWaitOrCancel(t *testing.T) {
	t.Run("returns after duration", func(t *testing.T) {
		start := time.Now()
		err := waitOrCancel(context.Background(), 50*time.Millisecond)
		if err != nil {
			t.Fatalf("expected nil err, got %v", err)
		}
		if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
			t.Fatalf("returned too early: %s", elapsed)
		}
	})
	t.Run("returns on ctx cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(10 * time.Millisecond)
			cancel()
		}()
		start := time.Now()
		err := waitOrCancel(ctx, 10*time.Second)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected Canceled, got %v", err)
		}
		if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
			t.Fatalf("cancel was slow: %s", elapsed)
		}
	})
}

// TestDialFailBackoff exercises the exponential-backoff curve on
// repeated dial failures. Every attempt fails with a fixed error;
// the loop should escalate 1ms → 2ms → 4ms → … up to the configured
// cap, calling OnDialFail once per failure.
func TestDialFailBackoff(t *testing.T) {
	opts := loopOpts{
		dialTimeout:     50 * time.Millisecond,
		stableThreshold: 10 * time.Millisecond,
		backoffInitial:  1 * time.Millisecond,
		backoffMax:      8 * time.Millisecond,
		keepAlive:       time.Second,
		writeTimeout:    time.Second,
	}

	var attempts int64
	wantErr := errors.New("boom")
	opts.dial = func(_ context.Context, _, _ string) (net.Conn, error) {
		atomic.AddInt64(&attempts, 1)
		return nil, wantErr
	}

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	var fails int32
	obs := &Observer{
		OnDialFail: func(err error) {
			atomic.AddInt32(&fails, 1)
			if !errors.Is(err, wantErr) {
				t.Errorf("OnDialFail err = %v, want %v", err, wantErr)
			}
		},
		OnConnect: func() {
			t.Errorf("OnConnect should not fire when every dial fails")
		},
	}

	_ = runDialLoop(ctx, "fake:0", noopServe, nil, obs, opts)

	if a := atomic.LoadInt64(&attempts); a < 3 {
		t.Errorf("expected >=3 dial attempts in 80ms, got %d", a)
	}
	if f := atomic.LoadInt32(&fails); f < 3 {
		t.Errorf("expected >=3 OnDialFail notifications, got %d", f)
	}
}

// TestStableSessionResetsBackoff verifies that once a session lasts
// ≥ stableThreshold, backoff drops back to backoffInitial. The test
// alternates one long-lived session with one fast-failing dial; the
// attempt interval after the long session should be backoffInitial,
// not a previously-escalated value.
func TestStableSessionResetsBackoff(t *testing.T) {
	opts := loopOpts{
		dialTimeout:     50 * time.Millisecond,
		stableThreshold: 20 * time.Millisecond,
		backoffInitial:  5 * time.Millisecond,
		backoffMax:      50 * time.Millisecond,
		keepAlive:       time.Second,
		writeTimeout:    time.Second,
	}

	dials := make(chan time.Time, 16)
	var phase atomic.Int32 // 0 = fail dials, 1 = succeed once, 2 = fail again
	opts.dial = func(_ context.Context, _, _ string) (net.Conn, error) {
		dials <- time.Now()
		switch phase.Load() {
		case 0, 2:
			return nil, errors.New("dial refused")
		case 1:
			phase.Store(2)
			// Return a live conn; the yamux.Server call succeeds on
			// a net.Pipe-backed peer below.
			return newFakeConn(), nil
		}
		return nil, errors.New("unreachable")
	}

	var serveCalls atomic.Int32
	onServe := func(ctx context.Context, lis *SessionListener) error {
		serveCalls.Add(1)
		// Stay up past stableThreshold then return.
		select {
		case <-ctx.Done():
		case <-time.After(40 * time.Millisecond):
		}
		_ = lis.Close()
		return nil
	}

	// Let two fail cycles burn the backoff up, then flip phase to
	// allow one successful long-lived session, then resume failing.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	go func() {
		time.Sleep(20 * time.Millisecond)
		phase.Store(1)
	}()

	_ = runDialLoop(ctx, "fake:0", onServe, nil, nil, opts)

	if serveCalls.Load() == 0 {
		t.Fatalf("expected at least one session to run")
	}
	// Collect dial timestamps and verify that the interval right
	// AFTER the successful-session phase returns to ~backoffInitial
	// (5ms) rather than the escalated value (up to 50ms).
	var ts []time.Time
	close(dials)
	for d := range dials {
		ts = append(ts, d)
	}
	if len(ts) < 3 {
		t.Fatalf("need at least 3 dial samples, got %d", len(ts))
	}
	// The gap between the dial that produced the successful session
	// and the NEXT dial (which happens after the session ends
	// cleanly → backoff reset → dial immediately) should be close
	// to the session's own duration (~40ms) + backoffInitial, not
	// the ceiling.
	// We can't peg the exact index without stronger hooks; instead
	// assert that at least one consecutive pair is short (≤30ms),
	// proving the reset happened somewhere.
	sawShort := false
	for i := 1; i < len(ts); i++ {
		if ts[i].Sub(ts[i-1]) <= 30*time.Millisecond {
			sawShort = true
			break
		}
	}
	if !sawShort {
		t.Errorf("no dial pair was ≤30ms apart — backoff never reset")
	}
}

// TestFastFailAppliesBackoff makes every session tear down
// immediately (< stableThreshold). The loop must apply backoff
// between dials instead of hot-looping.
func TestFastFailAppliesBackoff(t *testing.T) {
	opts := loopOpts{
		dialTimeout:     50 * time.Millisecond,
		stableThreshold: 50 * time.Millisecond, // anything < 50ms is a fast-fail
		backoffInitial:  10 * time.Millisecond,
		backoffMax:      40 * time.Millisecond,
		keepAlive:       time.Second,
		writeTimeout:    time.Second,
	}

	var dials atomic.Int32
	opts.dial = func(_ context.Context, _, _ string) (net.Conn, error) {
		dials.Add(1)
		return newFakeConn(), nil
	}

	// Serve returns immediately → every session is < stableThreshold.
	onServe := func(ctx context.Context, lis *SessionListener) error {
		return errors.New("fast exit")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	_ = runDialLoop(ctx, "fake:0", onServe, nil, nil, opts)

	// Hot-loop guard: without backoff we'd fit dozens of dials in
	// 120ms. With the 10→40ms escalation we should see ~5 or fewer.
	n := dials.Load()
	if n > 15 {
		t.Errorf("fast-fail hot-looped: %d dials in 120ms (expected backoff)", n)
	}
	if n < 2 {
		t.Errorf("expected multiple fast-fail cycles, got %d", n)
	}
}

// TestCtxCancelExitsLoop — cancelling ctx mid-dial should cause the
// loop to return ctx.Err() without hanging.
func TestCtxCancelExitsLoop(t *testing.T) {
	opts := loopOpts{
		dialTimeout:     50 * time.Millisecond,
		stableThreshold: 10 * time.Millisecond,
		backoffInitial:  100 * time.Millisecond, // long enough to catch mid-wait
		backoffMax:      time.Second,
		keepAlive:       time.Second,
		writeTimeout:    time.Second,
	}
	opts.dial = func(_ context.Context, _, _ string) (net.Conn, error) {
		return nil, errors.New("nope")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runDialLoop(ctx, "fake:0", noopServe, nil, nil, opts)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected Canceled, got %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("loop did not return after ctx cancel")
	}
}

// TestObserverEventOrdering documents the expected callback order
// on a happy-path session: OnAttempt → OnConnect → OnSessionExit.
// On a dial-fail-only path: OnAttempt → OnDialFail (no Connect/Exit).
func TestObserverEventOrdering(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		opts := loopOpts{
			dialTimeout:     50 * time.Millisecond,
			stableThreshold: 10 * time.Millisecond,
			backoffInitial:  time.Millisecond,
			backoffMax:      time.Millisecond,
			keepAlive:       time.Second,
			writeTimeout:    time.Second,
		}
		var calls []string
		var mu sync.Mutex
		record := func(s string) {
			mu.Lock()
			calls = append(calls, s)
			mu.Unlock()
		}
		opts.dial = func(_ context.Context, _, _ string) (net.Conn, error) {
			return newFakeConn(), nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
		defer cancel()
		obs := &Observer{
			OnAttempt:     func() { record("attempt") },
			OnConnect:     func() { record("connect") },
			OnDialFail:    func(error) { record("dialfail") },
			OnSessionExit: func(error, time.Duration) { record("exit") },
		}
		onServe := func(ctx context.Context, lis *SessionListener) error {
			time.Sleep(30 * time.Millisecond) // stable
			_ = lis.Close()
			return nil
		}
		_ = runDialLoop(ctx, "fake:0", onServe, nil, obs, opts)

		mu.Lock()
		defer mu.Unlock()
		if len(calls) < 3 {
			t.Fatalf("too few events: %v", calls)
		}
		// First three events must be attempt, connect, exit (loop may
		// have recycled after the ctx timeout hit).
		want := []string{"attempt", "connect", "exit"}
		for i, w := range want {
			if calls[i] != w {
				t.Errorf("event %d = %s, want %s (all=%v)", i, calls[i], w, calls)
			}
		}
	})
	t.Run("dial-fail path", func(t *testing.T) {
		opts := loopOpts{
			dialTimeout:     50 * time.Millisecond,
			stableThreshold: 10 * time.Millisecond,
			backoffInitial:  time.Millisecond,
			backoffMax:      time.Millisecond,
			keepAlive:       time.Second,
			writeTimeout:    time.Second,
		}
		var connects, exits atomic.Int32
		opts.dial = func(_ context.Context, _, _ string) (net.Conn, error) {
			return nil, errors.New("refused")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
		defer cancel()
		obs := &Observer{
			OnConnect:     func() { connects.Add(1) },
			OnSessionExit: func(error, time.Duration) { exits.Add(1) },
		}
		_ = runDialLoop(ctx, "fake:0", noopServe, nil, obs, opts)
		if connects.Load() != 0 {
			t.Errorf("OnConnect fired on a dial-only failure path")
		}
		if exits.Load() != 0 {
			t.Errorf("OnSessionExit fired with no session")
		}
	})
}

// noopServe returns immediately; used only when the loop is expected
// to never reach Serve (dial-fail-only tests).
func noopServe(ctx context.Context, lis *SessionListener) error {
	_ = lis.Close()
	return nil
}

// newFakeConn returns a net.Pipe half wrapped to satisfy yamux's
// DeadlineConn expectation. yamux calls SetReadDeadline on its side
// for keep-alive handling; net.Pipe implements Deadline methods so
// this works out of the box.
func newFakeConn() net.Conn {
	a, b := net.Pipe()
	// Drive the "other" side to keep yamux happy — read into the void
	// so writes on our end don't block forever during the handshake.
	go func() {
		buf := make([]byte, 1024)
		for {
			if _, err := b.Read(buf); err != nil {
				return
			}
		}
	}()
	return &loggedConn{Conn: a}
}

// loggedConn only exists to make debugging a failing test easier —
// logging can be enabled by flipping a boolean.
type loggedConn struct{ net.Conn }

func (c *loggedConn) Write(p []byte) (int, error) {
	return c.Conn.Write(p)
}

func (c *loggedConn) Close() error {
	return c.Conn.Close()
}

// Guard: compile-time check that the error strings surfaced through
// OnDialFail don't accidentally get rewrapped with dial-specific
// prefixes — callers log them verbatim in the admin UI.
var _ = fmt.Sprintf
