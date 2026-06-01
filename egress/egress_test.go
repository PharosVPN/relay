// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package egress

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeOpener hands out a single pre-made substream end — enough for one Open.
type fakeOpener struct{ conn net.Conn }

func (f *fakeOpener) OpenStream(context.Context) (net.Conn, error) { return f.conn, nil }

// TestOpenServeRoundTrip drives the whole path over an in-memory substream:
// coxswain Opens to a target, the relay Serves it against a real echo backend,
// and bytes flow both ways verbatim — proving the relay is a transparent pipe.
func TestOpenServeRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(c, c) // echo
		_ = c.Close()
	}()

	coxEnd, relayEnd := net.Pipe()
	go func() {
		dial := func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
		_ = Serve(context.Background(), relayEnd, dial)
	}()

	conn, err := Open(context.Background(), &fakeOpener{conn: coxEnd}, ln.Addr().String())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello through the relay")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Errorf("echo = %q, want %q", got, msg)
	}
}

// TestReadTargetStopsAtNewline proves the preamble reader does not consume the
// tunneled payload that follows the target line.
func TestReadTargetStopsAtNewline(t *testing.T) {
	r := strings.NewReader("10.0.0.9:8444\nPAYLOAD-AFTER")
	addr, err := readTarget(r)
	if err != nil {
		t.Fatalf("readTarget: %v", err)
	}
	if addr != "10.0.0.9:8444" {
		t.Errorf("addr = %q, want 10.0.0.9:8444", addr)
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "PAYLOAD-AFTER" {
		t.Errorf("payload after target = %q, want PAYLOAD-AFTER (reader over-consumed)", rest)
	}
}

func TestReadTargetRejects(t *testing.T) {
	cases := map[string]string{
		"no newline before EOF": "1.2.3.4:443",
		"bad host:port":         "not-a-target\n",
		"empty host":            ":443\n",
		"bad port":              "1.2.3.4:notaport\n",
		"oversized":             strings.Repeat("x", maxTargetLen+10) + "\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := readTarget(strings.NewReader(in)); err == nil {
				t.Errorf("readTarget(%q) = nil error, want rejection", in)
			}
		})
	}
}

func TestValidateTarget(t *testing.T) {
	ok := []string{"1.2.3.4:443", "node.example:8444", "[2001:db8::1]:8444"}
	for _, a := range ok {
		if err := validateTarget(a); err != nil {
			t.Errorf("validateTarget(%q) = %v, want nil", a, err)
		}
	}
	bad := []string{"", "1.2.3.4", "host:", "host:0", "host:70000", ":443"}
	for _, a := range bad {
		if err := validateTarget(a); err == nil {
			t.Errorf("validateTarget(%q) = nil, want error", a)
		}
	}
}

// TestOpenRejectsBadTargetBeforeStream proves Open validates the target before
// it ever touches the tunnel — a malformed addr must not open a substream.
func TestOpenRejectsBadTargetBeforeStream(t *testing.T) {
	opener := &fakeOpener{conn: nil} // OpenStream would panic if reached
	if _, err := Open(context.Background(), opener, "garbage"); err == nil {
		t.Fatal("Open with bad target = nil error, want rejection")
	}
}
