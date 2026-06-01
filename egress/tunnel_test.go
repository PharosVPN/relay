// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package egress

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// newEchoServer starts a TCP echo backend and returns its address. It stands in
// for a buoy node the relay dials.
func newEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(c, c); _ = c.Close() }(c)
		}
	}()
	return ln.Addr().String()
}

// TestTunnelRoundTrip wires the whole egress transport over a TCP socket pair:
// coxswain (yamux client) opens substreams to the relay (AcceptAndServe), which
// dials the echo backend. Two independent streams prove multiplexing — one
// tunnel carries many concurrent coxswain→node dials.
func TestTunnelRoundTrip(t *testing.T) {
	backend := newEchoServer(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	relayConnCh := make(chan net.Conn, 1)
	go func() {
		if c, err := ln.Accept(); err == nil {
			relayConnCh <- c
		}
	}()
	coxConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	relayConn := <-relayConnCh

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	go func() { _ = AcceptAndServe(ctx, relayConn, dial) }()

	client, err := NewClientSession(coxConn)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	for i := 0; i < 2; i++ {
		conn, err := Open(ctx, client, backend)
		if err != nil {
			t.Fatalf("Open #%d: %v", i, err)
		}
		msg := []byte(fmt.Sprintf("ping-%d", i))
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("write #%d: %v", i, err)
		}
		got := make([]byte, len(msg))
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("read #%d: %v", i, err)
		}
		if !bytes.Equal(got, msg) {
			t.Errorf("stream #%d echo = %q, want %q", i, got, msg)
		}
		_ = conn.Close()
	}
}
