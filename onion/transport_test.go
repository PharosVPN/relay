// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package onion_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/PharosVPN/beacon/onion"
)

func plainDial(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func echoServer(t *testing.T) string {
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

// startRelay runs an onion relay (plain-TCP listener calling Serve with priv).
func startRelay(t *testing.T, ctx context.Context, priv *ecdh.PrivateKey) string {
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
			go func(c net.Conn) { _ = onion.Serve(ctx, c, priv, plainDial) }(c)
		}
	}()
	return ln.Addr().String()
}

// TestOnionTransportThreeHops drives the full onion data path: coxswain Opens a
// 3-hop circuit to an echo backend; each relay peels its setup layer, forwards,
// and pumps the layered stream; bytes round-trip intact — proving setup + data
// phase + the relay Serve loop compose end to end.
func TestOnionTransportThreeHops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := echoServer(t)
	hops := make([]onion.Hop, 3)
	for i := range hops {
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		hops[i] = onion.Hop{Addr: startRelay(t, ctx, priv), OnionPub: priv.PublicKey()}
	}

	conn, err := onion.Open(ctx, hops, backend, plainDial)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer conn.Close()

	msg := []byte("control-plane bytes through a 3-hop onion")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Errorf("echo through onion = %q, want %q", got, msg)
	}
}

// TestOnionRelayDropsForeignSetup proves a relay drops a connection whose setup
// was not sealed to its key — the plain listener is not an open relay.
func TestOnionRelayDropsForeignSetup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	addr := startRelay(t, ctx, priv)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Framed garbage (2-byte len + bytes) that is not a valid sealed layer.
	_, _ = c.Write([]byte{0, 8, 1, 2, 3, 4, 5, 6, 7, 8})
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("relay served a foreign setup, want the connection dropped")
	}
}
