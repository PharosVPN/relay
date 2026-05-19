// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/PharosVPN/beacon/tunnel"
)

// serverTLS builds a TLS server config presenting certPEM and
// requiring a client cert that chains to trustPEM.
func serverTLS(t *testing.T, certPEM, keyPEM, trustPEM []byte) *tls.Config {
	t.Helper()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(trustPEM) {
		t.Fatal("server trust pool not parseable")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
}

// clientTLS builds a TLS client config presenting certPEM and pinning
// serverName against trustPEM.
func clientTLS(t *testing.T, certPEM, keyPEM, trustPEM []byte, serverName string) *tls.Config {
	t.Helper()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(trustPEM) {
		t.Fatal("client trust pool not parseable")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}
}

// TestRemoteRelay exercises the remote transport end to end: helm
// dials OUT to the relay's tunnel listener, the relay forwards each
// caravel RPC as a yamux substream back through that one connection,
// and helm serves its gRPC server on the multiplexed substreams.
func TestRemoteRelay(t *testing.T) {
	p := newPKI(t)
	helm := newFakeHelm(t, p.helmCertPEM, p.helmKeyPEM, p.fleetCA.certPEM)

	ctx, cancel := context.WithCancel(context.Background())

	// beacon side: a TLS tunnel listener helm dials into.
	tcpLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tunnel listen: %v", err)
	}
	tunnelLis := tls.NewListener(tcpLis,
		serverTLS(t, p.relayCertPEM, p.relayKeyPEM, p.fleetCA.certPEM))
	tunnelAddr := tcpLis.Addr().String()

	// helm side: dial OUT and serve the gRPC server on each session.
	helmTLS := clientTLS(t, p.helmCertPEM, p.helmKeyPEM, p.fleetCA.certPEM, "beacon")
	go func() {
		_ = tunnel.DialAndAcceptLoop(ctx, tunnelAddr, helmTLS,
			func(_ context.Context, lis *tunnel.SessionListener) error {
				return helm.srv.Serve(lis)
			}, nil, nil)
	}()

	// beacon side: accept helm's tunnel connection.
	ctCh := make(chan *tunnel.ClientTunnel, 1)
	go func() {
		ct, acceptErr := tunnel.AcceptOne(ctx, tunnelLis)
		if acceptErr != nil {
			t.Errorf("accept tunnel: %v", acceptErr)
			close(ctCh)
			return
		}
		ctCh <- ct
	}()

	var ct *tunnel.ClientTunnel
	select {
	case ct = <-ctCh:
		if ct == nil {
			t.Fatal("tunnel accept failed")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the tunnel")
	}

	// Tear down in reverse: stop helm so DialAndAcceptLoop unblocks,
	// then cancel ctx so the loop exits, then close the listener.
	t.Cleanup(func() {
		helm.srv.Stop()
		cancel()
		_ = tunnelLis.Close()
	})

	// The relay forwards each caravel RPC over a fresh tunnel substream.
	cfg := p.relayConfig("127.0.0.1:0", func(dctx context.Context, _ string) (net.Conn, error) {
		return ct.Open(dctx)
	})
	r, err := Start(cfg)
	if err != nil {
		t.Fatalf("start relay: %v", err)
	}
	t.Cleanup(r.Stop)

	cc := dialThrough(t, r.Addr().String(),
		caravelClientTLS(t, p.fleetCA.certPEM, p.caravelCertPEM, p.caravelKeyPEM, "beacon"))
	t.Cleanup(func() { _ = cc.Close() })

	callCtx, callCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer callCancel()

	resp, err := unaryCall(callCtx, cc, "/pharos.account.v1.AccountSync/GetProfile", nil, []byte("ping"))
	if err != nil {
		t.Fatalf("unary call over tunnel: %v", err)
	}
	if string(resp) != "helm:ping" {
		t.Errorf("response = %q, want %q", resp, "helm:ping")
	}
	if got := helm.metadataValue(deviceFPMetadataKey); got != fingerprintOf(t, p.caravelCertPEM) {
		t.Errorf("device-fp = %q, want verified fingerprint", got)
	}
}
