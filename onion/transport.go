// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package onion

import (
	"context"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// maxSetupLen bounds the nested setup onion a relay will read.
const maxSetupLen = 64 * 1024

// Dialer dials the next hop — the next relay's onion listener for a middle hop,
// or the node for the exit. Plain TCP: the onion itself supplies confidentiality
// (setup sealed to each relay's key, data layered), so the hop links need no TLS.
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// Serve handles one inbound onion connection on a relay. It reads the framed
// setup onion, Peels this hop's layer with priv, dials the next hop, forwards
// the inner setup (a middle hop only), then pumps the data stream both ways
// through this hop's layer. It blocks until a side closes and always closes conn.
//
// A connection whose setup was not sealed to priv fails to Peel and is dropped,
// so the plain-TCP listener is not an open relay — only coxswain, which knows
// the relays' onion public keys, can build a valid circuit.
func Serve(ctx context.Context, conn net.Conn, priv *ecdh.PrivateKey, dial Dialer) error {
	defer conn.Close()

	setup, err := readFramed(conn)
	if err != nil {
		return fmt.Errorf("onion: read setup: %w", err)
	}
	peeled, err := Peel(setup, priv)
	if err != nil {
		return err
	}
	layer, err := NewLayer(peeled.Key)
	if err != nil {
		return err
	}

	next, err := dial(ctx, "tcp", peeled.NextAddr)
	if err != nil {
		return fmt.Errorf("onion: dial next %s: %w", peeled.NextAddr, err)
	}
	defer next.Close()

	if !peeled.Exit {
		// Hand the inner onion to the next relay as its setup.
		if err := writeFramed(next, peeled.Inner); err != nil {
			return fmt.Errorf("onion: forward setup: %w", err)
		}
	}
	pump(conn, next, layer)
	return nil
}

// pump runs this hop's bidirectional data phase: forward (prev→next) peels this
// layer; return (next→prev) adds it. Both conns close on first EOF.
func pump(prev, next net.Conn, layer *Layer) {
	done := make(chan struct{}, 2)
	go func() { copyXOR(next, prev, layer.Forward); done <- struct{}{} }()
	go func() { copyXOR(prev, next, layer.Return); done <- struct{}{} }()
	<-done
	_ = prev.Close()
	_ = next.Close()
	<-done
}

// copyXOR copies src→dst, applying xform to every chunk in place (in stream
// order, so the keystream counter stays aligned across hops).
func copyXOR(dst io.Writer, src io.Reader, xform func([]byte)) {
	buf := make([]byte, 32*1024)
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			xform(buf[:n])
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if rerr != nil {
			return
		}
	}
}

// Open builds a circuit through hops to target, dials the first hop with dial,
// sends the setup onion, and returns a net.Conn that layers every write (toward
// the node) and unwraps every read (from the node) — i.e. coxswain's end of the
// circuit. dial reaches only the first hop; the relays chain the rest.
func Open(ctx context.Context, hops []Hop, target string, dial Dialer) (net.Conn, error) {
	circ, err := Build(hops, target)
	if err != nil {
		return nil, err
	}
	stack, err := NewStack(circ.Keys)
	if err != nil {
		return nil, err
	}
	conn, err := dial(ctx, "tcp", hops[0].Addr)
	if err != nil {
		return nil, fmt.Errorf("onion: dial first hop %s: %w", hops[0].Addr, err)
	}
	if err := writeFramed(conn, circ.Setup); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("onion: send setup: %w", err)
	}
	return &layeredConn{Conn: conn, stack: stack}, nil
}

// layeredConn is coxswain's end: writes are wrapped in all layers, reads are
// unwrapped from all layers.
type layeredConn struct {
	net.Conn
	stack *Stack
}

func (c *layeredConn) Write(p []byte) (int, error) {
	buf := make([]byte, len(p))
	copy(buf, p)
	c.stack.Forward(buf)
	n, err := c.Conn.Write(buf)
	if n > len(p) {
		n = len(p)
	}
	return n, err
}

func (c *layeredConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.stack.Return(p[:n])
	}
	return n, err
}

func writeFramed(w io.Writer, b []byte) error {
	if len(b) > maxSetupLen {
		return errors.New("onion: setup too large")
	}
	if _, err := w.Write(binary.BigEndian.AppendUint16(nil, uint16(len(b)))); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

func readFramed(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if int(n) > maxSetupLen {
		return nil, errors.New("onion: setup too large")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}
