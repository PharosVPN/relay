// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package onion_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/PharosVPN/relay/onion"
)

// genHops returns n relay hops with fresh X25519 onion keys, plus their private
// keys (the relays' secrets).
func genHops(t *testing.T, n int) ([]onion.Hop, []*ecdh.PrivateKey) {
	t.Helper()
	hops := make([]onion.Hop, n)
	privs := make([]*ecdh.PrivateKey, n)
	for i := range hops {
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		privs[i] = priv
		hops[i] = onion.Hop{Addr: fmt.Sprintf("relay%d.example:8456", i), OnionPub: priv.PublicKey()}
	}
	return hops, privs
}

// TestBuildPeelUnwindsPath builds a circuit and peels it hop by hop, proving the
// path unwinds correctly, each relay learns ONLY its next hop, and coxswain's
// derived session keys match what each relay recovers (essential for the data
// phase).
func TestBuildPeelUnwindsPath(t *testing.T) {
	const n = 3
	hops, privs := genHops(t, n)
	target := "10.0.0.9:8444"

	circ, err := onion.Build(hops, target)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(circ.Keys) != n {
		t.Fatalf("Keys = %d, want %d", len(circ.Keys), n)
	}

	setup := circ.Setup
	for i := 0; i < n; i++ {
		p, err := onion.Peel(setup, privs[i])
		if err != nil {
			t.Fatalf("Peel hop %d: %v", i, err)
		}
		if !bytes.Equal(p.Key, circ.Keys[i]) {
			t.Errorf("hop %d session key mismatch between coxswain and relay", i)
		}
		if i < n-1 {
			if p.Exit {
				t.Errorf("hop %d wrongly marked exit", i)
			}
			if p.NextAddr != hops[i+1].Addr {
				t.Errorf("hop %d next = %q, want %q", i, p.NextAddr, hops[i+1].Addr)
			}
			if len(p.Inner) == 0 {
				t.Errorf("hop %d has no inner onion", i)
			}
			setup = p.Inner
		} else {
			if !p.Exit {
				t.Errorf("last hop not marked exit")
			}
			if p.NextAddr != target {
				t.Errorf("exit target = %q, want %q", p.NextAddr, target)
			}
			if len(p.Inner) != 0 {
				t.Errorf("exit inner = %d bytes, want 0", len(p.Inner))
			}
		}
	}
}

// TestPeelWrongKeyFails proves a relay cannot open a layer sealed to a different
// relay — a coerced relay learns nothing beyond its own hop.
func TestPeelWrongKeyFails(t *testing.T) {
	hops, privs := genHops(t, 2)
	circ, err := onion.Build(hops, "1.2.3.4:8444")
	if err != nil {
		t.Fatal(err)
	}
	// hop 1's key must not open hop 0's outer layer.
	if _, err := onion.Peel(circ.Setup, privs[1]); err == nil {
		t.Fatal("Peel with the wrong relay key succeeded, want failure")
	}
}

func TestBuildRejectsBadInput(t *testing.T) {
	hops, _ := genHops(t, 1)
	if _, err := onion.Build(nil, "1.2.3.4:8444"); err == nil {
		t.Error("Build(nil hops) = nil error")
	}
	if _, err := onion.Build(hops, ""); err == nil {
		t.Error("Build(empty target) = nil error")
	}
}
