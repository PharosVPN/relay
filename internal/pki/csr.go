// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Package pki handles beacon's relay-side certificate material: it
// generates the relay's mTLS keypair on the host and emits a
// certificate signing request.
//
// The relay's private key is generated here and never leaves the host.
// helm signs the CSR with the Fleet CA and pushes back the relay
// certificate and the two trust anchors over SSH (DESIGN §5, decision
// 14 — CSR-over-SSH, no bootstrap token).
//
// The CSR is deliberately plain: it carries only the public key. helm
// is the sole authority on the relay's identity and overrides the
// subject and SANs when it signs — Subject O="PharosVPN Relay" (the
// pinned delegation marker, which a relay host must not self-assert),
// dual ServerAuth+ClientAuth EKU, and the public-endpoint DNS SAN. See
// helm/BUILD.md, "Relay enrollment contract".
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// keyFileMode is restrictive: the relay private key is readable only by
// its owner. It never leaves the host.
const keyFileMode = 0o600

// csrSubject is a human-readable label only. helm ignores the CSR
// subject entirely and assigns the real identity at signing time —
// crucially Organization, which carries the delegation marker and must
// not be self-asserted by the relay host.
var csrSubject = pkix.Name{CommonName: "pharos-beacon-relay"}

// CSRResult is the outcome of GenerateCSR.
type CSRResult struct {
	// CSRPEM is the PEM-encoded PKCS#10 certificate request, for helm
	// to sign.
	CSRPEM []byte
	// KeyGenerated reports whether a new private key was created. It is
	// false when an existing key at keyPath was reused.
	KeyGenerated bool
}

// GenerateCSR ensures a relay private key exists at keyPath and returns
// a certificate signing request built from it.
//
// If keyPath already holds a key it is reused, making `beacon gen-csr`
// idempotent: re-running it after a failed enrolment emits a fresh CSR
// for the same key rather than orphaning the old one. The parent
// directory is created if missing.
func GenerateCSR(keyPath string) (CSRResult, error) {
	key, generated, err := loadOrCreateKey(keyPath)
	if err != nil {
		return CSRResult{}, err
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            csrSubject,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		return CSRResult{}, fmt.Errorf("pki: create CSR: %w", err)
	}
	return CSRResult{
		CSRPEM:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		KeyGenerated: generated,
	}, nil
}

// loadOrCreateKey returns the relay private key at keyPath, generating
// and persisting a new ECDSA P-256 key if none exists.
func loadOrCreateKey(keyPath string) (*ecdsa.PrivateKey, bool, error) {
	switch existing, err := os.ReadFile(keyPath); {
	case err == nil:
		key, err := parseECKey(existing)
		if err != nil {
			return nil, false, fmt.Errorf("pki: existing key %s: %w", keyPath, err)
		}
		return key, false, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, false, fmt.Errorf("pki: read %s: %w", keyPath, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("pki: generate key: %w", err)
	}
	if err := writeKey(keyPath, key); err != nil {
		return nil, false, err
	}
	return key, true, nil
}

// writeKey persists key as a PKCS#8 PEM file with owner-only
// permissions.
func writeKey(keyPath string, key *ecdsa.PrivateKey) error {
	if dir := filepath.Dir(keyPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("pki: create %s: %w", dir, err)
		}
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("pki: marshal key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(keyPath, pemBytes, keyFileMode); err != nil {
		return fmt.Errorf("pki: write %s: %w", keyPath, err)
	}
	return nil
}

// parseECKey decodes a PKCS#8 PEM-encoded ECDSA private key.
func parseECKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("not a PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA key (%T)", parsed)
	}
	return key, nil
}
