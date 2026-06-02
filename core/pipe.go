// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package core

import (
	"context"
	"errors"
	"net"
	"sync"
)

// Pipe is the embedded-mode transport: an in-memory net.Conn pair
// factory that is both a net.Listener and a dialer. coxswain serves its
// gRPC server on the Pipe (it implements net.Listener) and sets
// Config.BackendDialer to Pipe.DialContext. Each backend connection
// the relay opens becomes a net.Pipe whose other end is handed to the
// listener's Accept — no TCP, no loopback hop, but full TLS still
// runs over it so embedded and remote modes share one trust path.
type Pipe struct {
	conns     chan net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

// NewPipe returns a ready Pipe. Close it to unblock a blocked
// Accept/DialContext and stop the embedded relay's backend.
func NewPipe() *Pipe {
	return &Pipe{
		conns:  make(chan net.Conn),
		closed: make(chan struct{}),
	}
}

// DialContext satisfies the Config.BackendDialer signature. It mints a
// net.Pipe, hands the far end to a pending Accept, and returns the
// near end. The addr argument is ignored.
func (p *Pipe) DialContext(ctx context.Context, _ string) (net.Conn, error) {
	near, far := net.Pipe()
	select {
	case p.conns <- far:
		return near, nil
	case <-ctx.Done():
		_ = near.Close()
		_ = far.Close()
		return nil, ctx.Err()
	case <-p.closed:
		_ = near.Close()
		_ = far.Close()
		return nil, errPipeClosed
	}
}

// Accept returns the next dialed connection. It blocks until a
// DialContext call pairs with it, or returns an error once the Pipe
// is closed. Satisfies net.Listener.
func (p *Pipe) Accept() (net.Conn, error) {
	select {
	case c := <-p.conns:
		return c, nil
	case <-p.closed:
		return nil, errPipeClosed
	}
}

// Close shuts the Pipe down. Idempotent. Satisfies net.Listener.
func (p *Pipe) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

// Addr reports the Pipe's synthetic address. Satisfies net.Listener.
func (p *Pipe) Addr() net.Addr { return pipeAddr{} }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "relay-embedded-pipe" }

var errPipeClosed = errors.New("relay: embedded pipe closed")
