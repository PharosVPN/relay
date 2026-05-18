// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"bytes"
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
