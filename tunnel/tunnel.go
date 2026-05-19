// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Package tunnel is the reverse-tunnel transport between helm (the
// controller) and a remote beacon relay.
//
// Why it exists: beacon is the only public surface (clients dial it).
// helm lives wherever it's safe — home LAN, private VPC, laptop —
// behind whatever NAT / firewall, with zero inbound ports (DESIGN §2).
// Without this package, a remote beacon would have to dial INTO helm's
// mTLS port, meaning helm needs a public IP + open inbound. That's the
// anti-pattern this fixes: helm dials OUT to beacon.
//
// Wire direction:
//
//	helm  ── TCP+mTLS ──▶  beacon:tunnel-port   (long-lived, retried)
//	  (yamux Server, accepts)        (yamux Client, opens)
//
//	client ── mTLS ──▶ beacon:public ── yamux substream ──▶ helm
//	                   (package relay)               (helm's grpc.Server)
//
// helm's grpc.Server doesn't know the tunnel exists. Every accepted
// yamux substream on the helm side looks like an incoming TCP conn to
// it — [SessionListener] adapts the yamux session to a standard
// net.Listener.
//
// This package is TLS-agnostic: helm builds the *tls.Config it dials
// with, and beacon wraps its tunnel listener with tls.NewListener
// before handing it to AcceptOne. The tunnel leg is mutually
// authenticated — helm presents a Fleet-CA leaf carrying
// Organization="PharosVPN Relay" (the pinned delegation marker, see
// package relay), beacon presents its Fleet-CA relay cert. The inner
// gRPC stream that rides the substreams is independently mTLS'd; that
// inner cert is what helm's gRPC auth interceptor reads for delegation.
//
// Scope for v1: one helm per beacon, one beacon per helm. Multi-tenant
// fan-in (several controllers behind one relay) needs a routing layer
// on the relay side and is deferred.
package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// SessionListener adapts a yamux.Session so it satisfies net.Listener.
// Each Accept returns the next incoming substream as a net.Conn.
// Closing the listener closes the underlying session; Addr returns
// the session's LocalAddr.
//
// Used on the helm side: the outbound tunnel conn is wrapped in
// yamux.Server (helm accepts substreams); this listener hands those
// substreams to grpc.Server.Serve as if they were regular TCP
// accepts.
type SessionListener struct {
	sess   *yamux.Session
	addr   net.Addr
	once   sync.Once
	closed chan struct{}
}

// NewSessionListener wraps sess. [sess] must already be in Server
// mode (i.e. created via yamux.Server for the side that accepts).
func NewSessionListener(sess *yamux.Session) *SessionListener {
	return &SessionListener{
		sess:   sess,
		addr:   sess.LocalAddr(),
		closed: make(chan struct{}),
	}
}

// Accept returns the next incoming substream. Blocks until a client
// RPC triggers the relay to open a new yamux stream, or until the
// session dies (returns error), or until Close is called.
func (l *SessionListener) Accept() (net.Conn, error) {
	stream, err := l.sess.Accept()
	if err != nil {
		return nil, err
	}
	return stream, nil
}

// Close tears down the yamux session. Idempotent.
func (l *SessionListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.sess.Close()
}

// Addr returns the underlying tunnel's local address. gRPC's Server
// uses this only for log lines.
func (l *SessionListener) Addr() net.Addr { return l.addr }

// Done signals when the session has been closed (by us or by the
// remote side). Callers use this to drive reconnect logic.
func (l *SessionListener) Done() <-chan struct{} { return l.closed }

// Observer is the optional event sink used by DialAndAcceptLoop to
// surface state transitions to the caller. All fields are optional;
// nil means "don't notify." Used by helm to keep per-relay metrics
// (attempt counter, last error, last-attempt timestamp) that the
// admin UI reads back.
//
// The observer runs synchronously inside the loop — handlers must not
// block or they delay reconnects. Capture state into a mutex-guarded
// struct and return fast.
type Observer struct {
	OnAttempt     func()                                  // about to dial
	OnConnect     func()                                  // session established, healthy
	OnDialFail    func(err error)                         // tls/yamux failure before a session was up
	OnSessionExit func(err error, duration time.Duration) // session tore down; err may be nil
}

// dialerFn lets tests inject a non-TLS dial path. Defaults to TLS.
type dialerFn func(ctx context.Context, network, addr string) (net.Conn, error)

// loopOpts aggregates the tunables so test-only knobs stay out of the
// public API. Production callers use DialAndAcceptLoop with the
// hardcoded defaults.
type loopOpts struct {
	dial            dialerFn
	dialTimeout     time.Duration
	stableThreshold time.Duration
	backoffInitial  time.Duration
	backoffMax      time.Duration
	keepAlive       time.Duration
	writeTimeout    time.Duration
}

var defaultLoopOpts = loopOpts{
	// nil dial → DialAndAcceptLoop installs the TLS dialer.
	dialTimeout:     10 * time.Second,
	stableThreshold: 5 * time.Second,
	backoffInitial:  1 * time.Second,
	backoffMax:      60 * time.Second,
	keepAlive:       20 * time.Second,
	writeTimeout:    10 * time.Second,
}

// DialAndAcceptLoop is the helm-side entry point. It dials the relay
// over TLS, wraps the conn in yamux.Server, hands the resulting
// SessionListener to [onListener], and reconnects forever until ctx
// is cancelled.
//
// Resilience guarantees:
//
//   - TLS handshake is bounded by a 10s context — half-open connects
//     and silent-firewall-drops can't hang the loop forever.
//   - Dial failures feed an exponential backoff (1s → 60s), reset
//     only after a session stays up for ≥5s (the stable threshold).
//     Sessions that die within 5s count as a failed attempt and keep
//     the backoff growing, so we can't hot-loop against a relay that
//     accepts the TLS but immediately closes the yamux session.
//   - yamux keep-alive pings every 20s — a dead tunnel is detected
//     within ~20s without waiting for TCP RST (which can be minutes
//     behind a NAT / firewall).
//   - Every state transition is surfaced via [obs] (nil → silent) so
//     the admin UI can show attempts, last-error, uptime.
//
// [relayAddr] is "host:port" for the relay's TUNNEL listener (NOT the
// client-facing port). [onListener] must drive grpc.Server.Serve
// against the listener (blocks until session tears down).
func DialAndAcceptLoop(
	ctx context.Context,
	relayAddr string,
	tlsCfg *tls.Config,
	onListener func(ctx context.Context, lis *SessionListener) error,
	logf func(format string, args ...any),
	obs *Observer,
) error {
	opts := defaultLoopOpts
	opts.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Bounded-context TLS dial. DialContext respects the ctx
		// deadline for both TCP connect + TLS handshake, so a
		// stalled handshake can't hang the reconnect loop.
		d := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: opts.dialTimeout},
			Config:    tlsCfg,
		}
		return d.DialContext(ctx, network, addr)
	}
	return runDialLoop(ctx, relayAddr, onListener, logf, obs, opts)
}

func runDialLoop(
	ctx context.Context,
	relayAddr string,
	onListener func(ctx context.Context, lis *SessionListener) error,
	logf func(format string, args ...any),
	obs *Observer,
	opts loopOpts,
) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if obs == nil {
		obs = &Observer{}
	}

	backoff := opts.backoffInitial

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		if obs.OnAttempt != nil {
			obs.OnAttempt()
		}
		logf("[beacon] dialing relay %s", relayAddr)

		dialCtx, dialCancel := context.WithTimeout(ctx, opts.dialTimeout)
		conn, err := opts.dial(dialCtx, "tcp", relayAddr)
		dialCancel()
		if err != nil {
			logf("[beacon] dial failed: %v (retrying in %s)", err, backoff)
			if obs.OnDialFail != nil {
				obs.OnDialFail(err)
			}
			if waitErr := waitOrCancel(ctx, backoff); waitErr != nil {
				return waitErr
			}
			backoff = capBackoff(backoff*2, opts.backoffMax)
			continue
		}

		cfg := yamux.DefaultConfig()
		cfg.KeepAliveInterval = opts.keepAlive
		cfg.ConnectionWriteTimeout = opts.writeTimeout

		sess, err := yamux.Server(conn, cfg)
		if err != nil {
			_ = conn.Close()
			logf("[beacon] yamux.Server: %v", err)
			if obs.OnDialFail != nil {
				obs.OnDialFail(err)
			}
			if waitErr := waitOrCancel(ctx, backoff); waitErr != nil {
				return waitErr
			}
			backoff = capBackoff(backoff*2, opts.backoffMax)
			continue
		}

		logf("[beacon] tunnel established → %s", relayAddr)
		if obs.OnConnect != nil {
			obs.OnConnect()
		}

		lis := NewSessionListener(sess)
		sessionStart := time.Now()
		serveErr := onListener(ctx, lis)
		sessionDuration := time.Since(sessionStart)

		if serveErr != nil {
			logf("[beacon] session exited after %s: %v", sessionDuration.Round(time.Millisecond), serveErr)
		} else {
			logf("[beacon] session exited cleanly after %s", sessionDuration.Round(time.Millisecond))
		}
		if obs.OnSessionExit != nil {
			obs.OnSessionExit(serveErr, sessionDuration)
		}

		// Fast-fail detection: if the session didn't stay up for at
		// least stableThreshold, treat this as a failed attempt so we
		// don't hot-loop against a broken far side (e.g. relay
		// accepting the TLS but immediately closing yamux). Stable
		// sessions reset backoff to initial.
		if sessionDuration < opts.stableThreshold {
			logf("[beacon] session fast-failed (<%s); backing off %s before reconnect",
				opts.stableThreshold, backoff)
			if waitErr := waitOrCancel(ctx, backoff); waitErr != nil {
				return waitErr
			}
			backoff = capBackoff(backoff*2, opts.backoffMax)
		} else {
			backoff = opts.backoffInitial
		}
	}
}

// waitOrCancel blocks for d or until ctx is done. Returns ctx.Err()
// on cancel so the caller can exit the loop cleanly.
func waitOrCancel(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// capBackoff returns min(v, max). Extracted so the tests can cover
// the escalation curve directly.
func capBackoff(v, max time.Duration) time.Duration {
	if v > max {
		return max
	}
	return v
}

// ── Relay side ──────────────────────────────────────────────────────

// ClientTunnel is the relay-side handle to the helm tunnel. Open
// returns a new substream ("dial" helm) for each client RPC that
// arrives on the relay's public listener.
//
// Lifecycle: created by AcceptOne when helm dials in; replaced
// (atomically) if helm reconnects. Consumers should call Open on the
// current handle on every RPC instead of caching a substream, so a
// fresh reconnect is picked up cleanly.
type ClientTunnel struct {
	sess *yamux.Session
}

// Open returns the next substream to helm as a net.Conn. Zero
// buffering on creation — helm's grpc.Server.Serve accepts it within
// milliseconds. If the session is already torn down, returns a
// closed-session error from yamux.
func (t *ClientTunnel) Open(ctx context.Context) (net.Conn, error) {
	if t == nil || t.sess == nil {
		return nil, errors.New("tunnel: not connected")
	}
	stream, err := t.sess.Open()
	if err != nil {
		return nil, err
	}
	return stream, nil
}

// Closed reports whether the tunnel has been torn down. Relay callers
// poll this to refuse client RPCs early with a clean error instead of
// opening a stream that's about to fail.
func (t *ClientTunnel) Closed() bool {
	return t == nil || t.sess == nil || t.sess.IsClosed()
}

// Done returns a channel closed when the tunnel tears down, by either
// side. A relay supervisor selects on it to know when to accept the
// next helm connection, rather than polling Closed.
func (t *ClientTunnel) Done() <-chan struct{} {
	if t == nil || t.sess == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return t.sess.CloseChan()
}

// AcceptOne accepts ONE helm TLS connection from [lis], wraps it in
// yamux.Client mode, and returns the resulting ClientTunnel. The
// relay caller holds this tunnel handle and opens a substream per
// client RPC.
//
// Returns on Close, on ctx cancel, or after the first accept. Intent
// is "run this in a loop per relay-tunnel endpoint, swap the stored
// tunnel on each reconnect."
func AcceptOne(
	ctx context.Context,
	lis net.Listener,
) (*ClientTunnel, error) {
	if lis == nil {
		return nil, errors.New("tunnel: nil listener")
	}
	accepted := make(chan net.Conn, 1)
	accErr := make(chan error, 1)
	go func() {
		conn, err := lis.Accept()
		if err != nil {
			accErr <- err
			return
		}
		accepted <- conn
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-accErr:
		return nil, fmt.Errorf("accept: %w", err)
	case conn := <-accepted:
		cfg := yamux.DefaultConfig()
		cfg.KeepAliveInterval = 20 * time.Second
		cfg.ConnectionWriteTimeout = 10 * time.Second
		sess, err := yamux.Client(conn, cfg)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("yamux.Client: %w", err)
		}
		return &ClientTunnel{sess: sess}, nil
	}
}
