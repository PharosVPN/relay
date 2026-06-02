// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package onion_test

import (
	"path/filepath"
	"testing"

	"github.com/PharosVPN/relay/onion"
)

// TestLoadOrCreateKey proves the onion key is minted once and stably reloaded,
// and that its public key survives the base64 transport coxswain uses.
func TestLoadOrCreateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "onion.key")

	priv, created, err := onion.LoadOrCreateKey(path)
	if err != nil || !created {
		t.Fatalf("first LoadOrCreateKey: created=%v err=%v", created, err)
	}

	again, created2, err := onion.LoadOrCreateKey(path)
	if err != nil || created2 {
		t.Fatalf("second LoadOrCreateKey: created=%v err=%v", created2, err)
	}
	if priv.PublicKey().Equal(again.PublicKey()) == false {
		t.Error("reloaded onion key differs from the persisted one")
	}

	// Public key round-trips through the base64 form coxswain records + reads.
	b64 := onion.PublicKeyBase64(priv.PublicKey())
	parsed, err := onion.ParsePublicKey(b64)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if !parsed.Equal(priv.PublicKey()) {
		t.Error("public key did not round-trip through base64")
	}
	if _, err := onion.ParsePublicKey("not-base64!!"); err == nil {
		t.Error("ParsePublicKey accepted garbage")
	}
}
