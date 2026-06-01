// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

// byteCodec is an opaque gRPC codec for the integration tests: it
// moves *[]byte payloads verbatim, mirroring how the relay forwards
// frames without decoding them.
type byteCodec struct{}

func (byteCodec) Name() string { return "proto" }

func (byteCodec) Marshal(v any) ([]byte, error) {
	b, ok := v.(*[]byte)
	if !ok {
		return nil, fmt.Errorf("byteCodec: want *[]byte, got %T", v)
	}
	return *b, nil
}

func (byteCodec) Unmarshal(data []byte, v any) error {
	b, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("byteCodec: want *[]byte, got %T", v)
	}
	*b = append([]byte(nil), data...)
	return nil
}

// fakeCoxswain stands in for coxswain's gRPC server. It registers no service:
// an UnknownServiceHandler echoes every frame back with a "coxswain:"
// prefix and records the metadata of the most recent stream, so a
// test can assert what the relay forwarded.
type fakeCoxswain struct {
	srv *grpc.Server

	mu     sync.Mutex
	lastMD metadata.MD
}

// newFakeCoxswain builds a fakeCoxswain whose gRPC server requires mTLS:
// it presents coxswainCert and verifies client certs against trust.
func newFakeCoxswain(t *testing.T, coxswainCertPEM, coxswainKeyPEM, trustPEM []byte) *fakeCoxswain {
	t.Helper()
	cert, err := tls.X509KeyPair(coxswainCertPEM, coxswainKeyPEM)
	if err != nil {
		t.Fatalf("coxswain keypair: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(trustPEM) {
		t.Fatal("coxswain trust pool not parseable")
	}
	h := &fakeCoxswain{}
	h.srv = grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    pool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS13,
		})),
		grpc.ForceServerCodec(byteCodec{}),
		grpc.UnknownServiceHandler(h.handle),
	)
	return h
}

func (h *fakeCoxswain) handle(_ any, ss grpc.ServerStream) error {
	md, _ := metadata.FromIncomingContext(ss.Context())
	h.mu.Lock()
	h.lastMD = md
	h.mu.Unlock()
	for {
		var b []byte
		if err := ss.RecvMsg(&b); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		echo := append([]byte("coxswain:"), b...)
		if err := ss.SendMsg(&echo); err != nil {
			return err
		}
	}
}

// metadataValue returns the first value the last stream carried for
// key, or "" if absent.
func (h *fakeCoxswain) metadataValue(key string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if v := h.lastMD.Get(key); len(v) > 0 {
		return v[0]
	}
	return ""
}

// caravelClientTLS builds the TLS config a caravel client uses to
// reach the relay: it trusts relayTrust and pins serverName. When
// certPEM is nil the client connects without a certificate (the
// pre-enrolment path).
func caravelClientTLS(t *testing.T, relayTrust, certPEM, keyPEM []byte, serverName string) *tls.Config {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(relayTrust) {
		t.Fatal("caravel trust pool not parseable")
	}
	cfg := &tls.Config{
		RootCAs:    pool,
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}
	if certPEM != nil {
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("caravel keypair: %v", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg
}

// unaryCall makes one transparent unary RPC through cc, sending req
// and returning the response frame.
func unaryCall(ctx context.Context, cc *grpc.ClientConn, method string, md metadata.MD, req []byte) ([]byte, error) {
	if len(md) > 0 {
		ctx = metadata.NewOutgoingContext(ctx, md)
	}
	var resp []byte
	err := cc.Invoke(ctx, method, &req, &resp, grpc.ForceCodec(byteCodec{}))
	return resp, err
}

// dialThrough opens a client connection to addr over tlsCfg.
func dialThrough(t *testing.T, addr string, tlsCfg *tls.Config) *grpc.ClientConn {
	t.Helper()
	cc, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(byteCodec{})),
	)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	return cc
}
