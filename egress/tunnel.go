// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package egress

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

// Tunnel yamux tunables, matching the relay ingress tunnel: a 20s keep-alive
// detects a dead far side within ~20s without waiting on TCP RST (which can lag
// minutes behind a NAT), and a 10s write timeout bounds a stalled peer.
func yamuxCfg() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.KeepAliveInterval = 20 * time.Second
	cfg.ConnectionWriteTimeout = 10 * time.Second
	cfg.LogOutput = io.Discard
	return cfg
}

// AcceptAndServe runs the relay side of one egress tunnel. conn is an accepted
// coxswain connection (already TLS-terminated by the caller); this wraps it as
// a yamux server and serves every substream coxswain opens by reading its
// CONNECT target and dialing it with dial. It blocks until the session tears
// down (coxswain disconnects, keep-alive fails, or ctx is cancelled), then
// returns so the caller can accept the next coxswain connection.
//
// The substream direction is the inverse of the relay ingress tunnel: there
// the relay opens streams toward coxswain; here coxswain opens streams toward
// the relay and the relay dials out (DESIGN §3, decision 19).
func AcceptAndServe(ctx context.Context, conn net.Conn, dial Dialer) error {
	sess, err := yamux.Server(conn, yamuxCfg())
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("egress: yamux server: %w", err)
	}
	defer sess.Close()

	for {
		stream, err := sess.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("egress: accept substream: %w", err)
		}
		go func() { _ = Serve(ctx, stream, dial) }()
	}
}

// RunRelay serves egress tunnels accepted on lis, one coxswain at a time (v1:
// one controller per relay, matching the relay ingress tunnel). When a
// coxswain session ends it loops to accept the next. It returns when ctx is
// cancelled or lis stops accepting. dial is how the relay reaches nodes
// (typically (&net.Dialer{Timeout: …}).DialContext).
func RunRelay(ctx context.Context, lis net.Listener, dial Dialer, logf func(string, ...any)) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	go func() {
		<-ctx.Done()
		_ = lis.Close() // unblock Accept on cancel
	}()
	for {
		conn, err := lis.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("egress: accept coxswain: %w", err)
		}
		logf("[egress] coxswain connected from %s", conn.RemoteAddr())
		if err := AcceptAndServe(ctx, conn, dial); err != nil && ctx.Err() == nil {
			logf("[egress] session ended: %v", err)
		}
	}
}

// ClientSession is coxswain's side of an egress tunnel: a yamux client over an
// already-established (TLS) connection to the relay. Each OpenStream returns a
// fresh substream that egress.Open writes a CONNECT target to. It satisfies
// StreamOpener.
type ClientSession struct {
	sess *yamux.Session
}

// NewClientSession wraps an established relay connection in a yamux client.
func NewClientSession(conn net.Conn) (*ClientSession, error) {
	sess, err := yamux.Client(conn, yamuxCfg())
	if err != nil {
		return nil, fmt.Errorf("egress: yamux client: %w", err)
	}
	return &ClientSession{sess: sess}, nil
}

// OpenStream opens a new substream to the relay.
func (c *ClientSession) OpenStream(context.Context) (net.Conn, error) {
	return c.sess.Open()
}

// IsClosed reports whether the session has torn down (so a caller can re-dial).
func (c *ClientSession) IsClosed() bool { return c.sess == nil || c.sess.IsClosed() }

// Close tears the session down.
func (c *ClientSession) Close() error {
	if c.sess == nil {
		return nil
	}
	return c.sess.Close()
}
