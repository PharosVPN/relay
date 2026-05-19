// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVersionCommand confirms `beacon version` prints the build version and
// nothing else — helm parses this output verbatim after an SSH install.
func TestVersionCommand(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"version"})

	if err := root.Execute(); err != nil {
		t.Fatalf("execute version: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != version {
		t.Errorf("version output = %q, want %q", got, version)
	}
}

// TestRunCommandRegistered checks the relay `run` command is wired into
// the root command.
func TestRunCommandRegistered(t *testing.T) {
	for _, c := range newRootCmd().Commands() {
		if c.Name() == "run" {
			return
		}
	}
	t.Error("run command is not registered")
}

// TestLoadMaterialMissing confirms a missing config dir yields a clear
// error rather than a panic.
func TestLoadMaterialMissing(t *testing.T) {
	if _, err := loadMaterial(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("loadMaterial accepted a missing config dir")
	}
}

// TestLoadMaterialComplete confirms a fully-staged config dir loads.
func TestLoadMaterialComplete(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{fileDeviceCA, fileFleetCA, fileRelayCrt, fileRelayKey} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("pem-"+f), 0o600); err != nil {
			t.Fatalf("stage %s: %v", f, err)
		}
	}
	m, err := loadMaterial(dir)
	if err != nil {
		t.Fatalf("loadMaterial: %v", err)
	}
	if string(m.relayCert) != "pem-"+fileRelayCrt {
		t.Errorf("relayCert = %q, want %q", m.relayCert, "pem-"+fileRelayCrt)
	}
}

// TestGenCSRCommand confirms `beacon gen-csr` writes the relay key into
// the config dir and prints only a CSR PEM to stdout — helm captures
// that stdout verbatim over SSH.
func TestGenCSRCommand(t *testing.T) {
	dir := t.TempDir()
	root := newRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs([]string{"gen-csr", "--config-dir", dir})

	if err := root.Execute(); err != nil {
		t.Fatalf("execute gen-csr: %v", err)
	}
	if got := out.String(); !strings.HasPrefix(got, "-----BEGIN CERTIFICATE REQUEST-----") {
		t.Errorf("stdout is not a CSR PEM: %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, fileRelayKey)); err != nil {
		t.Errorf("relay key not written: %v", err)
	}
}
