// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package proxy

import (
	"bytes"
	"testing"
)

// TestRawCodecRoundTrip confirms the opaque codec returns the exact
// bytes it was handed — the relay must never mutate a payload it
// forwards, and Unmarshal must copy so a reused buffer can't corrupt
// an in-flight frame.
func TestRawCodecRoundTrip(t *testing.T) {
	c := rawCodec{}
	want := []byte("opaque ciphertext profile bundle")

	wire, err := c.Marshal(&frame{data: want})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Equal(wire, want) {
		t.Fatalf("marshal mutated payload: got %q, want %q", wire, want)
	}

	var got frame
	if err := c.Unmarshal(wire, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !bytes.Equal(got.data, want) {
		t.Fatalf("unmarshal payload = %q, want %q", got.data, want)
	}

	// Unmarshal must copy, not alias the source buffer.
	wire[0] = 'X'
	if got.data[0] == 'X' {
		t.Error("unmarshal aliased the source buffer instead of copying")
	}
}

// TestRawCodecTypeConfusion verifies the codec fails loudly rather
// than silently mishandling a value that is not a *frame.
func TestRawCodecTypeConfusion(t *testing.T) {
	c := rawCodec{}
	if _, err := c.Marshal("not a frame"); err == nil {
		t.Error("Marshal accepted a non-*frame value")
	}
	if err := c.Unmarshal([]byte("x"), "not a frame"); err == nil {
		t.Error("Unmarshal accepted a non-*frame value")
	}
}

// TestCodecName pins the registered name to "proto" — the codec must
// shadow the default proto codec only on streams the relay creates.
func TestCodecName(t *testing.T) {
	if got := (rawCodec{}).Name(); got != "proto" {
		t.Errorf("codec name = %q, want %q", got, "proto")
	}
}

// TestMethodName checks the gRPC method-path trimming used as the
// forwarded StreamDesc name.
func TestMethodName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/pharos.account.v1.Sync/PullProfiles", "PullProfiles"},
		{"PullProfiles", "PullProfiles"},
		{"", ""},
	}
	for _, c := range cases {
		if got := methodName(c.in); got != c.want {
			t.Errorf("methodName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
