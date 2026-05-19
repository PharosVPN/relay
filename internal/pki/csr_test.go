// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package pki

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// TestGenerateCSRFresh confirms a first run writes an owner-only key
// and emits a CSR whose public key matches it.
func TestGenerateCSRFresh(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "relay.key")

	res, err := GenerateCSR(keyPath)
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	if !res.KeyGenerated {
		t.Error("KeyGenerated = false on a fresh key")
	}

	// The key file must exist and be readable only by its owner — the
	// relay private key never leaves the host.
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != keyFileMode {
		t.Errorf("key file mode = %o, want %o", perm, keyFileMode)
	}

	csr := parseCSR(t, res.CSRPEM)
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature invalid: %v", err)
	}

	// The CSR's public key must be the one on disk.
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	key, err := parseECKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	csrPub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("CSR public key is %T, want *ecdsa.PublicKey", csr.PublicKey)
	}
	if !csrPub.Equal(&key.PublicKey) {
		t.Error("CSR public key does not match the on-disk key")
	}
}

// TestGenerateCSRIdempotent confirms a second run reuses the existing
// key — re-running gen-csr after a failed enrolment must not orphan it.
func TestGenerateCSRIdempotent(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "relay.key")

	if _, err := GenerateCSR(keyPath); err != nil {
		t.Fatalf("first GenerateCSR: %v", err)
	}
	first, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}

	res, err := GenerateCSR(keyPath)
	if err != nil {
		t.Fatalf("second GenerateCSR: %v", err)
	}
	if res.KeyGenerated {
		t.Error("KeyGenerated = true on the second run; key was not reused")
	}
	second, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("re-read key: %v", err)
	}
	if string(first) != string(second) {
		t.Error("key file changed across runs")
	}
}

// TestGenerateCSRPlainSubject confirms the CSR does not self-assert the
// delegation Organization — helm is the sole authority on relay
// identity and assigns it at signing time.
func TestGenerateCSRPlainSubject(t *testing.T) {
	res, err := GenerateCSR(filepath.Join(t.TempDir(), "relay.key"))
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	csr := parseCSR(t, res.CSRPEM)
	if len(csr.Subject.Organization) != 0 {
		t.Errorf("CSR carries Organization %v; it must not self-assert one",
			csr.Subject.Organization)
	}
	if len(csr.DNSNames) != 0 {
		t.Errorf("CSR carries SANs %v; helm sets the hostname", csr.DNSNames)
	}
}

// TestGenerateCSRRejectsBadKey confirms a corrupt key file surfaces a
// clear error instead of silently minting a new key.
func TestGenerateCSRRejectsBadKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "relay.key")
	if err := os.WriteFile(keyPath, []byte("not a key"), keyFileMode); err != nil {
		t.Fatalf("write bad key: %v", err)
	}
	if _, err := GenerateCSR(keyPath); err == nil {
		t.Error("GenerateCSR accepted a corrupt key file")
	}
}

func parseCSR(t *testing.T, csrPEM []byte) *x509.CertificateRequest {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatal("output is not a CERTIFICATE REQUEST PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	return csr
}
