// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package relay is the embeddable PharosVPN relay: a stateless,
// transparent gRPC proxy that terminates Device-CA mTLS from caravel
// clients and forwards opaque gRPC streams to a coxswain controller
// (DESIGN §2, §3).
//
// # Two transports, identical trust
//
// coxswain reaches the relay's backend over a caller-supplied dialer, so
// the same relay code serves both deployment modes (DESIGN §2 —
// "transport differences only, identical trust"):
//
//   - Embedded: coxswain runs the relay in-process and sets
//     Config.BackendDialer to a [Pipe], an in-memory net.Conn pair.
//   - Remote: a relay binary runs the relay on a public host; coxswain
//     dials OUT to it over a reverse tunnel (package
//     github.com/PharosVPN/relay/tunnel) and the relay sets
//     Config.BackendDialer to a closure over the tunnel substreams.
//
// Either way the backend leg is mutually authenticated gRPC: the
// relay presents a delegation client leaf, coxswain verifies it. The
// relay never dials coxswain directly — coxswain has no inbound ports.
//
// # What the relay does
//
// It registers no gRPC services. Every inbound stream — unary,
// server-stream, client-stream, bidi — hits an UnknownServiceHandler
// that forwards it verbatim through an opaque byte codec. The relay
// never decodes a message body, so adding a coxswain RPC needs zero relay
// changes. It strips every client-supplied metadata key in the
// reserved x-pharos-* namespace and injects exactly one trusted value
// — the verified device fingerprint as x-pharos-device-fp.
//
// # Compromise containment
//
// The relay terminates the client's mTLS, so a compromised remote
// host can read RPC framing and metadata. Profile bundles, however,
// cross the relay end-to-end encrypted — coxswain seals each bundle to
// the user's key and only the user's device decrypts it (DESIGN §8).
// A compromised remote relay yields traffic metadata, never user
// profiles, and holds no CA key, so it cannot mint certs.
//
// # Pinned relay↔coxswain identifiers
//
// The metadata keys, the delegation cert Organization, and the
// backend SNI are part of the relay↔coxswain contract coxswain owns and
// pins in coxswain/BUILD.md. See proxy.go for the exact values.
package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// defaultBackendServerName is the SNI / leaf CN the relay expects on
// coxswain's gRPC-leg server certificate. Pinned — see coxswain/BUILD.md.
const defaultBackendServerName = "coxswain-grpc"

// maxMsgSize bounds a single forwarded gRPC message. Profile bundles
// are kilobytes; the ceiling is generous headroom, not a target.
const maxMsgSize = 16 * 1024 * 1024

// Config configures a relay. All certificate material is PEM. The two
// legs carry distinct trust roots because PharosVPN runs two CA
// intermediates (DESIGN §4): caravel clients present Device-CA leaves,
// while coxswain presents a Fleet-CA leaf.
type Config struct {
	// ClientListenAddr is the public address the relay binds for
	// caravel mTLS clients, e.g. ":8443". Required.
	ClientListenAddr string

	// RelayCertPEM / RelayKeyPEM is the relay's single Fleet-CA leaf.
	// It is presented on the public listener (server-auth) and on the
	// coxswain backend leg (client-auth), so it MUST carry both the
	// ServerAuth and ClientAuth EKUs and Organization="PharosVPN
	// Relay" — coxswain's auth path keys delegation off that Organization.
	// One cert for both legs is the pinned relay↔coxswain contract
	// (coxswain/BUILD.md). Required.
	RelayCertPEM []byte
	RelayKeyPEM  []byte

	// ClientTrustPEM is the CA pool used to verify caravel client
	// certificates — the Device CA. Required.
	ClientTrustPEM []byte

	// BackendTrustPEM is the CA pool used to verify coxswain's gRPC-leg
	// server certificate — the Fleet CA. Required.
	BackendTrustPEM []byte

	// BackendServerName is the SNI / verification name for the coxswain
	// dial. Defaults to "coxswain-grpc".
	BackendServerName string

	// BackendDialer returns a transport to coxswain's gRPC server. It is
	// invoked once per backend connection (and again by gRPC on
	// reconnect). Required.
	//
	//   - Embedded mode: (*Pipe).DialContext.
	//   - Remote mode:   a closure that opens a tunnel substream.
	//
	// The addr argument is an internal placeholder; the dialer should
	// ignore it.
	BackendDialer func(ctx context.Context, addr string) (net.Conn, error)

	// Logf is an optional log sink. nil discards.
	Logf func(format string, args ...any)
}

func (c *Config) validate() error {
	switch {
	case c.ClientListenAddr == "":
		return errors.New("relay: Config.ClientListenAddr required")
	case len(c.RelayCertPEM) == 0 || len(c.RelayKeyPEM) == 0:
		return errors.New("relay: Config.Relay{Cert,Key}PEM required")
	case len(c.ClientTrustPEM) == 0:
		return errors.New("relay: Config.ClientTrustPEM required")
	case len(c.BackendTrustPEM) == 0:
		return errors.New("relay: Config.BackendTrustPEM required")
	case c.BackendDialer == nil:
		return errors.New("relay: Config.BackendDialer required")
	}
	return nil
}

// Relay is a running relay: a public mTLS listener, the transparent
// gRPC server, and the single backend connection to coxswain. Construct
// it with Start and tear it down with Stop.
type Relay struct {
	listener net.Listener
	grpc     *grpc.Server
	backend  *grpc.ClientConn
	logf     func(string, ...any)
}

// Start binds the public listener, opens the backend connection to
// coxswain, and begins serving. It returns once the listener is bound;
// streams are served on a background goroutine. The backend dial is
// lazy — gRPC connects on the first forwarded RPC.
func Start(cfg Config) (*Relay, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	clientTLS, err := buildClientTLS(cfg)
	if err != nil {
		return nil, fmt.Errorf("relay: build client tls: %w", err)
	}
	backend, err := dialBackend(cfg)
	if err != nil {
		return nil, fmt.Errorf("relay: open backend: %w", err)
	}

	lis, err := net.Listen("tcp", cfg.ClientListenAddr)
	if err != nil {
		_ = backend.Close()
		return nil, fmt.Errorf("relay: listen %s: %w", cfg.ClientListenAddr, err)
	}

	// ForceServerCodec passes inbound frames through unmodified
	// (rawCodec). UnknownServiceHandler catches every method — the
	// relay Registers nothing, so that handler is the only path.
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(clientTLS)),
		grpc.ForceServerCodec(rawCodec{}),
		grpc.UnknownServiceHandler((&director{backend: backend}).handle),
		grpc.MaxRecvMsgSize(maxMsgSize),
		grpc.MaxSendMsgSize(maxMsgSize),
	)

	r := &Relay{listener: lis, grpc: srv, backend: backend, logf: logf}
	go func() {
		logf("[relay] relay serving caravel clients on %s", lis.Addr())
		if err := srv.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			logf("[relay] relay serve: %v", err)
		}
	}()
	return r, nil
}

// Addr is the bound public listener address — useful when
// ClientListenAddr used :0.
func (r *Relay) Addr() net.Addr {
	if r == nil || r.listener == nil {
		return nil
	}
	return r.listener.Addr()
}

// Stop gracefully drains in-flight streams and closes the backend
// connection. Idempotent.
func (r *Relay) Stop() {
	if r == nil {
		return
	}
	if r.grpc != nil {
		r.grpc.GracefulStop()
	}
	if r.backend != nil {
		_ = r.backend.Close()
	}
}

// buildClientTLS configures the public listener's mTLS. The relay
// presents its Fleet-CA leaf and accepts caravel clients with or
// without a certificate: pre-enrolment devices have no Device-CA leaf
// yet, so the relay must let them complete the handshake and defer
// the identity decision to coxswain. Any certificate that IS presented
// must chain to the Device CA.
func buildClientTLS(cfg Config) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(cfg.RelayCertPEM, cfg.RelayKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse relay keypair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cfg.ClientTrustPEM) {
		return nil, errors.New("ClientTrustPEM not parseable")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		// Public-facing: TLS 1.2 floor so the broad range of mobile
		// TLS stacks interoperates. The security boundary is the CA
		// pin caravel verifies on this leaf, not the protocol version.
		MinVersion: tls.VersionTLS12,
	}, nil
}

// dialBackend opens the single long-lived gRPC connection to coxswain.
// Every forwarded stream multiplexes over it. The connection always
// rides Config.BackendDialer (an in-memory pipe or a tunnel
// substream) — the relay never dials coxswain by address, so the gRPC
// target is an inert passthrough placeholder.
func dialBackend(cfg Config) (*grpc.ClientConn, error) {
	cert, err := tls.X509KeyPair(cfg.RelayCertPEM, cfg.RelayKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse relay keypair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cfg.BackendTrustPEM) {
		return nil, errors.New("BackendTrustPEM not parseable")
	}
	serverName := cfg.BackendServerName
	if serverName == "" {
		serverName = defaultBackendServerName
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}
	return grpc.NewClient(
		"passthrough:///"+serverName,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithContextDialer(cfg.BackendDialer),
		grpc.WithDefaultCallOptions(
			grpc.ForceCodec(rawCodec{}),
			grpc.MaxCallRecvMsgSize(maxMsgSize),
			grpc.MaxCallSendMsgSize(maxMsgSize),
		),
	)
}
