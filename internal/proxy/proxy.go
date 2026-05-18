// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Package proxy is the beacon relay's transparent gRPC proxy: it
// terminates Device-CA mTLS from a caravel client, reads the peer
// cert's fingerprint, and forwards every RPC — unary, server-stream,
// client-stream, bidi — to the helm controller's mTLS gRPC port.
//
// Why terminate mTLS on the relay instead of pass-through TCP:
//   - A L4 pass-through forces helm to be internet-reachable on its
//     mTLS port. We want beacon to be the only public surface so the
//     controller can live on a private network behind NAT (DESIGN §2).
//   - Termination lets us strip client-set x-pharos-* metadata so a
//     malicious client can't spoof identity, and inject the one value
//     helm actually needs: x-pharos-device-fp.
//   - Termination also gives us a chokepoint for future rate limits,
//     audit logging, or shedding without touching the controller.
//
// Compromise containment — beacon sees ciphertext, not profiles:
//
// Because the relay terminates the client's mTLS, anyone with root on
// a remote beacon host can read RPC framing and metadata in memory.
// Profile bundles, however, cross beacon end-to-end encrypted: helm
// encrypts each bundle to the user's public key and only the user's
// devices decrypt it (DESIGN §8, account-mode .pharos files §9). So a
// compromised remote beacon yields traffic metadata, never user
// profiles — and it holds no CA key, so it cannot mint certs
// (DESIGN §4 compromise table). For an embedded relay this is moot:
// it runs in the same process as helm.
//
// Why a transparent proxy instead of service-by-service registration:
//   - Every new helm RPC would otherwise need a stub on the relay.
//     A transparent proxy with grpc.UnknownServiceHandler forwards
//     anything — new service, new method, same day — zero changes.
//   - The relay never needs to parse message bodies, so encoding is
//     a raw byte codec (codec.go).
//
// Identity delegation protocol:
//
//	grpc-md: x-pharos-device-fp = sha256:<hex>
//
// helm's gRPC auth path reads that header when the presenting cert is
// a relay delegation leaf (Organization="PharosVPN Relay"), runs the
// device→user lookup itself, and stamps identity on the context. The
// relay holds NO device state — all lookups live on helm, so a
// remote-deployed beacon needs no access to the store or the CA
// private key.
//
// PINNED CONTRACT IDENTIFIERS. The metadata keys (x-pharos-device-fp,
// the x-pharos-* strip prefix), the delegation Organization marker
// ("PharosVPN Relay"), and the default backend SNI ("helm-grpc") are
// part of the beacon↔helm relayed-client contract. helm owns that
// contract and pins these identifiers in helm/BUILD.md ("Pinned
// beacon ↔ helm identifiers"); helm's M6b relayed-client proto and PKI
// use them exactly (docs/BUILD.md §3). Change them only in lockstep
// with helm.
package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// deviceFPMetadataKey is the one trusted metadata value beacon injects
// after verifying the client's Device-CA leaf. clientMetadataStrip is
// the prefix of client-set keys dropped before forwarding. delegationOrg
// is the Organization marker on the relay's backend client leaf that
// tells helm to trust the injected header. All three are pinned by the
// beacon↔helm contract — see the package doc.
const (
	deviceFPMetadataKey = "x-pharos-device-fp"
	clientMetadataStrip = "x-pharos-"
	delegationOrg       = "PharosVPN Relay"
)

// Deps names every external value the relay reaches for. Nothing is
// looked up from package globals or env vars at runtime.
//
// Deliberately PEM-only. The relay needs no access to the Device CA's
// private key and no direct database handle — both belong on helm. A
// remote beacon gets its material from helm during SSH enrollment
// (DESIGN §5):
//   - DeviceCAPEM: public CA cert, pinned on first use
//   - PublicServer{Cert,Key}PEM, BackendClient{Cert,Key}PEM:
//     issued by helm and pushed back over the SSH channel
//
// Device lookups (cert fingerprint → user) happen on the helm side
// via the x-pharos-device-fp metadata header.
type Deps struct {
	// DeviceCAPEM is the trust root for both sides. Used as ClientCAs
	// for the public listener and RootCAs for the backend dial.
	DeviceCAPEM []byte

	// Public-side leaf: server-auth cert the relay presents to
	// caravel clients. Issued by the Device CA.
	PublicServerCertPEM []byte
	PublicServerKeyPEM  []byte

	// Backend-side leaf: client-auth cert the relay presents to helm.
	// MUST carry Organization="PharosVPN Relay" so helm's auth path
	// recognises the delegation.
	BackendClientCertPEM []byte
	BackendClientKeyPEM  []byte

	// BackendAddr is where the relay forwards accepted streams.
	// In-host: "127.0.0.1:8443". Remote: "helm.internal:8443".
	// When BackendDialer is non-nil this can be any placeholder
	// string — gRPC still wants a target for resolver bookkeeping
	// but the dialer bypasses address resolution entirely.
	BackendAddr string

	// BackendServerName is the SNI/verification name the relay uses
	// when dialling helm. Must match helm's controller leaf CN
	// ("helm-grpc" by default).
	BackendServerName string

	// BackendDialer, when non-nil, replaces the default TCP dial.
	// Used by:
	//   - Embedded mode: hands the relay an in-memory (in-process
	//     pipe) route to a same-process helm gRPC backend — zero
	//     TCP-loopback hop, identical TLS semantics.
	//   - Remote reverse-tunnel mode: hands the relay a yamux-
	//     substream opener from internal/tunnel. Each client RPC
	//     opens a new yamux substream back through the single
	//     helm-initiated TLS conn, so helm can live behind NAT
	//     while beacon is the only public surface.
	//
	// If nil, the relay dials BackendAddr over TCP (direct path,
	// used only where helm has an inbound-reachable port).
	BackendDialer func(ctx context.Context, addr string) (net.Conn, error)
}

// Server is the public handle — listener + gRPC server + backend
// connection. Stop tears all three down.
type Server struct {
	listener net.Listener
	grpc     *grpc.Server
	backend  *grpc.ClientConn
}

// Start binds the relay on addr with mTLS and dials helm once — every
// forwarded stream multiplexes over that single HTTP/2 connection.
func Start(addr string, deps Deps) (*Server, error) {
	if len(deps.DeviceCAPEM) == 0 {
		return nil, errors.New("proxy: Deps.DeviceCAPEM required")
	}
	if len(deps.PublicServerCertPEM) == 0 || len(deps.PublicServerKeyPEM) == 0 {
		return nil, errors.New("proxy: Deps.PublicServer{Cert,Key}PEM required")
	}
	if len(deps.BackendClientCertPEM) == 0 || len(deps.BackendClientKeyPEM) == 0 {
		return nil, errors.New("proxy: Deps.BackendClient{Cert,Key}PEM required")
	}
	if deps.BackendAddr == "" {
		return nil, errors.New("proxy: Deps.BackendAddr required")
	}
	if deps.BackendServerName == "" {
		deps.BackendServerName = "helm-grpc"
	}

	publicTLS, err := buildPublicTLS(deps)
	if err != nil {
		return nil, fmt.Errorf("build public tls: %w", err)
	}

	backend, err := dialBackend(deps)
	if err != nil {
		return nil, fmt.Errorf("dial backend %s: %w", deps.BackendAddr, err)
	}

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		_ = backend.Close()
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}

	d := &director{backend: backend}

	// ForceServerCodec makes incoming frames pass through unmodified
	// (rawCodec). UnknownServiceHandler catches every method — we
	// never Register anything on this gRPC.Server, so unknown-service
	// is the only path that fires.
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(publicTLS)),
		grpc.ForceServerCodec(rawCodec{}),
		grpc.UnknownServiceHandler(d.handle),
		grpc.MaxRecvMsgSize(16*1024*1024),
		grpc.MaxSendMsgSize(16*1024*1024),
	)

	go func() {
		log.Printf("[beacon] relay listening on %s → %s", addr, deps.BackendAddr)
		if err := srv.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			log.Printf("[beacon] serve: %v", err)
		}
	}()

	return &Server{listener: lis, grpc: srv, backend: backend}, nil
}

// Stop drains in-flight streams and closes the backend conn.
func (s *Server) Stop() {
	if s == nil {
		return
	}
	if s.grpc != nil {
		s.grpc.GracefulStop()
	}
	if s.backend != nil {
		_ = s.backend.Close()
	}
}

// Addr exposes the bound listener address (handy for tests on :0).
func (s *Server) Addr() net.Addr {
	if s == nil || s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// ── TLS ────────────────────────────────────────────────────────────

// buildPublicTLS configures the relay's public-side mTLS: it presents
// the supplied server leaf (issued by the Device CA), and allows
// clients to connect with or without a cert — the enrolment carve-out
// needs the pre-cert path. Any cert that IS presented must chain to
// the Device CA.
func buildPublicTLS(deps Deps) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(deps.PublicServerCertPEM, deps.PublicServerKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse public keypair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(deps.DeviceCAPEM) {
		return nil, errors.New("device CA PEM not parseable")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		// VerifyClientCertIfGiven mirrors helm's own gRPC server:
		// pre-enrolment clients don't have a cert yet, so the relay
		// must let them through the TLS handshake and defer the
		// identity decision to the per-RPC director. Any cert that IS
		// presented must still chain to the Device CA.
		ClientAuth: tls.VerifyClientCertIfGiven,
		// Public-facing listener: TLS 1.2 minimum so a broad range of
		// mobile stacks interoperate. Android 10+ supports 1.3
		// natively but OEM crypto variants and some OkHttp / gRPC
		// wrappers drop to 1.2 or misnegotiate; rejecting them at
		// protocol_version costs us interop without buying anything
		// real — the security boundary here is the CA pin the client
		// verifies on the returned leaf, not the TLS version.
		// Internal hops (relay→helm) stay at 1.3 since those are
		// Go-to-Go and interop is guaranteed.
		MinVersion: tls.VersionTLS12,
	}, nil
}

// dialBackend opens one long-lived mTLS conn to helm using the
// supplied client leaf. helm's auth path recognises the leaf's
// O="PharosVPN Relay" marker and reads identity from the injected
// metadata headers instead of doing its own device lookup.
func dialBackend(deps Deps) (*grpc.ClientConn, error) {
	cert, err := tls.X509KeyPair(deps.BackendClientCertPEM, deps.BackendClientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse backend keypair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(deps.DeviceCAPEM) {
		return nil, errors.New("device CA PEM not parseable")
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   deps.BackendServerName,
		MinVersion:   tls.VersionTLS13,
	}
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithDefaultCallOptions(
			grpc.ForceCodec(rawCodec{}),
			grpc.MaxCallRecvMsgSize(16*1024*1024),
			grpc.MaxCallSendMsgSize(16*1024*1024),
		),
	}
	// Embedded / reverse-tunnel path: the dialer hands us a pre-wired
	// net.Conn (an in-process pipe for embedded mode, a yamux substream
	// for remote mode) so gRPC skips address resolution and TCP dial
	// entirely. TLS still runs over that conn — the delegation marker
	// on the relay's leaf is what helm's auth interceptor reads, and
	// we don't want two auth paths.
	if deps.BackendDialer != nil {
		opts = append(opts, grpc.WithContextDialer(deps.BackendDialer))
	}
	return grpc.NewClient(deps.BackendAddr, opts...)
}

// ── Stream director ────────────────────────────────────────────────

type director struct {
	backend *grpc.ClientConn
}

// handle is the UnknownServiceHandler entry point — gRPC calls this
// once per inbound stream for any (service, method) it can't match
// against a registered service. We open a matching stream on the
// backend and pump frames both directions.
func (d *director) handle(_ any, ss grpc.ServerStream) error {
	method, ok := grpc.MethodFromServerStream(ss)
	if !ok {
		return errMissingMethod
	}

	outCtx := d.buildOutgoingCtx(ss.Context())

	// ClientStream lets us receive from the peer and send to the
	// backend with symmetric API. gRPC picks unary vs streaming at
	// the wire level; we don't need to know which.
	desc := &grpc.StreamDesc{
		StreamName:    methodName(method),
		ServerStreams: true,
		ClientStreams: true,
	}
	clientStream, err := d.backend.NewStream(outCtx, desc, method)
	if err != nil {
		return err
	}

	return pipe(ss, clientStream)
}

// buildOutgoingCtx sanitises inbound metadata and injects the one
// value helm trusts us for: x-pharos-device-fp. Every x-pharos-* key
// the client might have set is stripped first, so a malicious client
// can't spoof identity by setting its own header.
//
// Pre-cert callers (enrolment) get the same sanitation minus the
// fingerprint injection. helm's anonymous-policy path handles them on
// the other end.
func (d *director) buildOutgoingCtx(in context.Context) context.Context {
	inMD, _ := metadata.FromIncomingContext(in)
	outMD := metadata.MD{}
	for k, v := range inMD {
		lower := strings.ToLower(k)
		if strings.HasPrefix(lower, clientMetadataStrip) {
			continue
		}
		if lower == "authorization" {
			continue
		}
		outMD[k] = v
	}
	if fp, err := fingerprintFromPeer(in); err == nil {
		outMD.Set(deviceFPMetadataKey, fp)
	}
	return metadata.NewOutgoingContext(in, outMD)
}

// pipe forwards frames in both directions until either side closes.
// Returns the first non-io.EOF error — that's what the client sees
// as the RPC status.
func pipe(in grpc.ServerStream, out grpc.ClientStream) error {
	// client → backend
	c2b := make(chan error, 1)
	go func() {
		for {
			f := &frame{}
			if err := in.RecvMsg(f); err != nil {
				if err == io.EOF {
					c2b <- out.CloseSend()
					return
				}
				c2b <- err
				return
			}
			if err := out.SendMsg(f); err != nil {
				c2b <- err
				return
			}
		}
	}()

	// Forward response headers before streaming body frames so gRPC
	// status codes on unary RPCs surface to the caller.
	hdr, err := out.Header()
	if err == nil && len(hdr) > 0 {
		_ = in.SendHeader(hdr)
	}

	// backend → client (inline — blocks until backend done)
	for {
		f := &frame{}
		if err := out.RecvMsg(f); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if err := in.SendMsg(f); err != nil {
			return err
		}
	}

	// trailers — status is already encoded here; gRPC passes it to
	// the client transparently.
	in.SetTrailer(out.Trailer())

	// reap client→backend side
	if err := <-c2b; err != nil && err != io.EOF {
		return err
	}
	return nil
}

// ── helpers ────────────────────────────────────────────────────────

// fingerprintFromPeer extracts the SHA-256 fingerprint of the peer's
// leaf cert. Same shape helm uses (sha256:<hex-of-PEM>) so helm and
// beacon agree without sharing code.
func fingerprintFromPeer(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return "", errNoPeer
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", errNoTLS
	}
	certs := tlsInfo.State.PeerCertificates
	if len(certs) == 0 {
		return "", errNoClientCert
	}
	return "sha256:" + certFingerprint(certs[0]), nil
}

func certFingerprint(c *x509.Certificate) string {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	h := sha256.Sum256(pemBytes)
	return hex.EncodeToString(h[:])
}

// methodName strips the leading "/service/" from a gRPC method path,
// leaving just the RPC method name. Used as StreamDesc.StreamName.
func methodName(fullMethod string) string {
	i := strings.LastIndex(fullMethod, "/")
	if i < 0 {
		return fullMethod
	}
	return fullMethod[i+1:]
}

var (
	errMissingMethod = errors.New("proxy: no method in server stream")
	errNoPeer        = errors.New("proxy: no peer info on context")
	errNoTLS         = errors.New("proxy: peer auth is not TLS")
	errNoClientCert  = errors.New("proxy: no client certificate")
)
