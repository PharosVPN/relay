// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package onion

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// keyFileMode keeps the onion private key owner-only.
const keyFileMode = 0o600

// LoadOrCreateKey returns the relay's persistent X25519 onion key, generating
// and writing it (0600) on first call. A relay Peels setup layers with the
// private key; coxswain records the matching public key at enrollment and seals
// each layer to it (DESIGN §3, decision 20). created reports whether a new key
// was minted, for the operator log.
func LoadOrCreateKey(path string) (priv *ecdh.PrivateKey, created bool, err error) {
	switch raw, rerr := os.ReadFile(path); {
	case rerr == nil:
		b, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if derr != nil {
			return nil, false, fmt.Errorf("onion: decode key %s: %w", path, derr)
		}
		priv, derr = ecdh.X25519().NewPrivateKey(b)
		if derr != nil {
			return nil, false, fmt.Errorf("onion: parse key %s: %w", path, derr)
		}
		return priv, false, nil
	case errors.Is(rerr, os.ErrNotExist):
		priv, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, false, fmt.Errorf("onion: generate key: %w", err)
		}
		if err := writeKey(path, priv); err != nil {
			return nil, false, err
		}
		return priv, true, nil
	default:
		return nil, false, fmt.Errorf("onion: read key %s: %w", path, rerr)
	}
}

// PublicKeyBase64 encodes an X25519 public key for transport (coxswain stores
// this string on the relay row at enrollment).
func PublicKeyBase64(pub *ecdh.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub.Bytes())
}

// ParsePublicKey decodes a base64 X25519 onion public key (coxswain reads it
// back from the relay row to Build a circuit).
func ParsePublicKey(s string) (*ecdh.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("onion: decode public key: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("onion: parse public key: %w", err)
	}
	return pub, nil
}

func writeKey(path string, priv *ecdh.PrivateKey) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("onion: create %s: %w", dir, err)
		}
	}
	enc := base64.StdEncoding.EncodeToString(priv.Bytes())
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(enc+"\n"), keyFileMode); err != nil {
		return fmt.Errorf("onion: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("onion: replace %s: %w", path, err)
	}
	return nil
}
