// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package relay

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// pki holds the certificate material an integration test needs. It
// models the two-intermediate PKI of DESIGN §4: caravel devices carry
// Device-CA leaves; the relay and helm carry Fleet-CA leaves.
type pki struct {
	fleetCA  *testCA
	deviceCA *testCA

	// relayCert is the Fleet-CA relay cert. It is presented on the
	// public listener (server-auth) and on the helm backend leg
	// (client-auth), and carries O="PharosVPN Relay".
	relayCertPEM, relayKeyPEM []byte

	// helmCert is helm's Fleet-CA leaf: gRPC-leg server cert
	// (CN/SAN "helm-grpc") and, for remote mode, tunnel client cert.
	helmCertPEM, helmKeyPEM []byte

	// caravelCert is a Device-CA device leaf.
	caravelCertPEM, caravelKeyPEM []byte
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	fleet := newTestCA(t, "PharosVPN Fleet CA")
	device := newTestCA(t, "PharosVPN Device CA")
	p := &pki{fleetCA: fleet, deviceCA: device}
	p.relayCertPEM, p.relayKeyPEM = fleet.leaf(t, leafOpts{
		cn: "beacon-relay", org: delegationOrg, dns: []string{"beacon"},
		server: true, client: true,
	})
	p.helmCertPEM, p.helmKeyPEM = fleet.leaf(t, leafOpts{
		cn: defaultBackendServerName, org: delegationOrg,
		dns: []string{defaultBackendServerName}, server: true, client: true,
	})
	p.caravelCertPEM, p.caravelKeyPEM = device.leaf(t, leafOpts{
		cn: "device-0001", client: true,
	})
	return p
}

// embeddedConfig is the relay Config common to embedded-mode tests.
func (p *pki) relayConfig(listenAddr string, dialer dialerFunc) Config {
	return Config{
		ClientListenAddr:  listenAddr,
		RelayCertPEM:      p.relayCertPEM,
		RelayKeyPEM:       p.relayKeyPEM,
		ClientTrustPEM:    p.deviceCA.certPEM,
		BackendTrustPEM:   p.fleetCA.certPEM,
		BackendServerName: defaultBackendServerName,
		BackendDialer:     dialer,
	}
}

type dialerFunc = func(ctx context.Context, addr string) (net.Conn, error)

// bidiStreamDesc describes a streaming RPC for the transparent client
// helpers — the relay forwards unary and streaming identically.
var bidiStreamDesc = &grpc.StreamDesc{
	StreamName:    "transparent",
	ServerStreams: true,
	ClientStreams: true,
}

// fingerprintOf parses a leaf PEM and returns the sha256:<hex> shape
// the relay injects, so a test can assert the forwarded value.
func fingerprintOf(t *testing.T, certPEM []byte) string {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("fingerprintOf: no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("fingerprintOf: parse: %v", err)
	}
	return "sha256:" + certFingerprint(cert)
}

// TestEmbeddedRelay exercises the embedded transport end to end: a
// caravel client → relay → helm over real mTLS, with helm reached
// through an in-memory Pipe. It asserts the payload round-trips and
// that metadata sanitization holds.
func TestEmbeddedRelay(t *testing.T) {
	p := newPKI(t)
	helm := newFakeHelm(t, p.helmCertPEM, p.helmKeyPEM, p.fleetCA.certPEM)
	pipe := NewPipe()
	t.Cleanup(func() { _ = pipe.Close() })

	go func() { _ = helm.srv.Serve(pipe) }()
	t.Cleanup(helm.srv.Stop)

	r, err := Start(p.relayConfig("127.0.0.1:0", pipe.DialContext))
	if err != nil {
		t.Fatalf("start relay: %v", err)
	}
	t.Cleanup(r.Stop)

	cc := dialThrough(t, r.Addr().String(),
		caravelClientTLS(t, p.fleetCA.certPEM, p.caravelCertPEM, p.caravelKeyPEM, "beacon"))
	t.Cleanup(func() { _ = cc.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The client tries to spoof a trusted header and an x-pharos-*
	// key, and sends a legitimate non-reserved header.
	spoof := metadata.MD{
		deviceFPMetadataKey: []string{"sha256:attacker-controlled"},
		"x-pharos-evil":     []string{"1"},
		"pharos-session":    []string{"tok-abc"},
	}
	resp, err := unaryCall(ctx, cc, "/pharos.account.v1.AccountSync/GetProfile", spoof, []byte("ping"))
	if err != nil {
		t.Fatalf("unary call: %v", err)
	}
	if string(resp) != "helm:ping" {
		t.Errorf("response = %q, want %q", resp, "helm:ping")
	}

	// The injected fingerprint must be the relay-verified one, not
	// whatever the client sent.
	wantFP := fingerprintOf(t, p.caravelCertPEM)
	if got := helm.metadataValue(deviceFPMetadataKey); got != wantFP {
		t.Errorf("device-fp = %q, want verified %q", got, wantFP)
	}
	// The reserved namespace must be fully stripped.
	if got := helm.metadataValue("x-pharos-evil"); got != "" {
		t.Errorf("spoofed x-pharos-evil survived: %q", got)
	}
	// Non-reserved metadata must pass through untouched.
	if got := helm.metadataValue("pharos-session"); got != "tok-abc" {
		t.Errorf("pharos-session = %q, want %q", got, "tok-abc")
	}
}

// TestEmbeddedRelayPreEnrolment confirms a client with no certificate
// — a device that has not enrolled yet — still reaches helm, just
// without an injected fingerprint.
func TestEmbeddedRelayPreEnrolment(t *testing.T) {
	p := newPKI(t)
	helm := newFakeHelm(t, p.helmCertPEM, p.helmKeyPEM, p.fleetCA.certPEM)
	pipe := NewPipe()
	t.Cleanup(func() { _ = pipe.Close() })
	go func() { _ = helm.srv.Serve(pipe) }()
	t.Cleanup(helm.srv.Stop)

	r, err := Start(p.relayConfig("127.0.0.1:0", pipe.DialContext))
	if err != nil {
		t.Fatalf("start relay: %v", err)
	}
	t.Cleanup(r.Stop)

	cc := dialThrough(t, r.Addr().String(),
		caravelClientTLS(t, p.fleetCA.certPEM, nil, nil, "beacon"))
	t.Cleanup(func() { _ = cc.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := unaryCall(ctx, cc, "/pharos.account.v1.AccountSync/Authenticate", nil, []byte("enrol"))
	if err != nil {
		t.Fatalf("unary call: %v", err)
	}
	if string(resp) != "helm:enrol" {
		t.Errorf("response = %q, want %q", resp, "helm:enrol")
	}
	if got := helm.metadataValue(deviceFPMetadataKey); got != "" {
		t.Errorf("device-fp injected for a certless client: %q", got)
	}
}

// TestEmbeddedRelayBidiStream exercises a streaming RPC: the relay
// must forward frames in both directions without decoding them.
func TestEmbeddedRelayBidiStream(t *testing.T) {
	p := newPKI(t)
	helm := newFakeHelm(t, p.helmCertPEM, p.helmKeyPEM, p.fleetCA.certPEM)
	pipe := NewPipe()
	t.Cleanup(func() { _ = pipe.Close() })
	go func() { _ = helm.srv.Serve(pipe) }()
	t.Cleanup(helm.srv.Stop)

	r, err := Start(p.relayConfig("127.0.0.1:0", pipe.DialContext))
	if err != nil {
		t.Fatalf("start relay: %v", err)
	}
	t.Cleanup(r.Stop)

	cc := dialThrough(t, r.Addr().String(),
		caravelClientTLS(t, p.fleetCA.certPEM, p.caravelCertPEM, p.caravelKeyPEM, "beacon"))
	t.Cleanup(func() { _ = cc.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := cc.NewStream(ctx, bidiStreamDesc, "/pharos.account.v1.AccountSync/Watch")
	if err != nil {
		t.Fatalf("new stream: %v", err)
	}
	for i, want := range []string{"helm:a", "helm:b", "helm:c"} {
		send := []byte{byte('a' + i)}
		if err := stream.SendMsg(&send); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		var got []byte
		if err := stream.RecvMsg(&got); err != nil {
			t.Fatalf("recv %d: %v", i, err)
		}
		if string(got) != want {
			t.Errorf("frame %d = %q, want %q", i, got, want)
		}
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close send: %v", err)
	}
}
