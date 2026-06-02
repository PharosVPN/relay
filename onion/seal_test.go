// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package onion_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/PharosVPN/relay/onion"
)

func randKeys(t *testing.T, n int) [][]byte {
	t.Helper()
	keys := make([][]byte, n)
	for i := range keys {
		keys[i] = make([]byte, onion.KeySize)
		if _, err := rand.Read(keys[i]); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

func relayLayers(t *testing.T, keys [][]byte) []*onion.Layer {
	t.Helper()
	ls := make([]*onion.Layer, len(keys))
	for i, k := range keys {
		l, err := onion.NewLayer(k)
		if err != nil {
			t.Fatal(err)
		}
		ls[i] = l
	}
	return ls
}

// TestDataPhaseForwardReturn proves the layered keystream round-trips: coxswain
// wraps a forward message in all layers and each relay peels one to recover the
// plaintext at the exit; the return path re-layers and coxswain unwraps it.
func TestDataPhaseForwardReturn(t *testing.T) {
	keys := randKeys(t, 3)

	// Forward: coxswain → R0 → R1 → R2(exit) → node.
	stack, _ := onion.NewStack(keys)
	relays := relayLayers(t, keys)
	msg := []byte("PUT /control through the onion circuit")
	buf := append([]byte(nil), msg...)
	stack.Forward(buf)
	if bytes.Equal(buf, msg) {
		t.Fatal("forward: coxswain did not encrypt")
	}
	for _, r := range relays { // hop 0 first peels the outer layer
		r.Forward(buf)
	}
	if !bytes.Equal(buf, msg) {
		t.Errorf("forward: exit plaintext = %q, want %q", buf, msg)
	}

	// Return: node → R2 → R1 → R0 → coxswain (fresh ciphers; they are stateful).
	stack2, _ := onion.NewStack(keys)
	relays2 := relayLayers(t, keys)
	resp := []byte("200 OK from the node")
	rbuf := append([]byte(nil), resp...)
	for i := len(relays2) - 1; i >= 0; i-- { // exit adds first, inward
		relays2[i].Return(rbuf)
	}
	if bytes.Equal(rbuf, resp) {
		t.Fatal("return: relays did not encrypt")
	}
	stack2.Return(rbuf)
	if !bytes.Equal(rbuf, resp) {
		t.Errorf("return: coxswain plaintext = %q, want %q", rbuf, resp)
	}
}

// TestEndToEndCircuit ties setup to data: Build derives the per-hop keys,
// each relay Peels the same key, and those keys drive the data phase — so a
// forward message wrapped by coxswain's Stack decrypts to plaintext after every
// relay peels its layer. This is the whole onion in one test.
func TestEndToEndCircuit(t *testing.T) {
	hops, privs := genHops(t, 3)
	circ, err := onion.Build(hops, "10.0.0.9:8444")
	if err != nil {
		t.Fatal(err)
	}

	relayKeys := make([][]byte, len(hops))
	setup := circ.Setup
	for i := range hops {
		p, err := onion.Peel(setup, privs[i])
		if err != nil {
			t.Fatalf("peel %d: %v", i, err)
		}
		relayKeys[i] = p.Key
		setup = p.Inner
	}

	stack, _ := onion.NewStack(circ.Keys) // coxswain uses the keys it derived
	relays := relayLayers(t, relayKeys)   // relays use the keys they peeled
	msg := []byte("end-to-end onion payload")
	buf := append([]byte(nil), msg...)
	stack.Forward(buf)
	for _, r := range relays {
		r.Forward(buf)
	}
	if !bytes.Equal(buf, msg) {
		t.Errorf("end-to-end forward failed: got %q want %q", buf, msg)
	}
}

// TestChunkedAlignment proves the keystream counters stay aligned when the
// stream is processed in arbitrary chunk boundaries (as a real pipe would).
func TestChunkedAlignment(t *testing.T) {
	keys := randKeys(t, 2)
	stack, _ := onion.NewStack(keys)
	relays := relayLayers(t, keys)

	msg := bytes.Repeat([]byte("pharos-onion-"), 100) // 1300 bytes
	buf := append([]byte(nil), msg...)
	stack.Forward(buf) // coxswain encrypts the whole buffer at once

	// Relays peel in uneven chunks.
	for _, r := range relays {
		for off := 0; off < len(buf); {
			end := off + 7
			if end > len(buf) {
				end = len(buf)
			}
			r.Forward(buf[off:end])
			off = end
		}
	}
	if !bytes.Equal(buf, msg) {
		t.Error("chunked peeling broke keystream alignment")
	}
}
