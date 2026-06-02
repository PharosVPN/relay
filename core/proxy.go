// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package core

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// Pinned relay↔coxswain identifiers. coxswain owns the relayed-client
// contract and pins these in coxswain/BUILD.md ("Pinned relay ↔ coxswain
// identifiers"); coxswain's M6b proto and PKI use them exactly. Change
// them only in lockstep with coxswain.
const (
	// deviceFPMetadataKey is the one trusted metadata value the relay
	// injects, after verifying the caravel client's Device-CA leaf.
	deviceFPMetadataKey = "x-pharos-device-fp"

	// clientMetadataStrip is the reserved namespace: every inbound
	// metadata key with this prefix is dropped before forwarding, so
	// a client cannot spoof deviceFPMetadataKey or any future trusted
	// key. The relay forwards all other metadata unchanged — it is a
	// transparent pipe outside this one namespace.
	clientMetadataStrip = "x-pharos-"

	// delegationOrg is the Organization on the relay's backend client
	// leaf. coxswain's gRPC auth path recognises it and reads identity
	// from the injected header instead of doing its own device lookup.
	delegationOrg = "PharosVPN Relay"
)

// director forwards every inbound gRPC stream to coxswain over the single
// backend connection. It is registered as the gRPC server's
// UnknownServiceHandler, so it catches every (service, method) pair —
// the relay registers no services of its own.
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

	outCtx := buildOutgoingCtx(ss.Context())

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

	return pipeFrames(ss, clientStream)
}

// buildOutgoingCtx sanitises inbound metadata and injects the one
// value coxswain trusts the relay for: x-pharos-device-fp. Every
// x-pharos-* key the client might have set is stripped first, so a
// malicious client cannot spoof identity by setting its own header.
//
// Pre-cert callers (enrolment, before the device holds a Device-CA
// leaf) get the same sanitation minus the fingerprint injection —
// coxswain's anonymous-policy path handles them on the other end.
func buildOutgoingCtx(in context.Context) context.Context {
	inMD, _ := metadata.FromIncomingContext(in)
	outMD := make(metadata.MD, len(inMD)+1)
	for k, v := range inMD {
		if strings.HasPrefix(strings.ToLower(k), clientMetadataStrip) {
			continue
		}
		outMD[k] = v
	}
	if fp, err := fingerprintFromPeer(in); err == nil {
		outMD.Set(deviceFPMetadataKey, fp)
	}
	return metadata.NewOutgoingContext(in, outMD)
}

// pipeFrames forwards opaque frames in both directions until either
// side closes. Returns the first non-io.EOF error — that is what the
// client sees as the RPC status.
func pipeFrames(in grpc.ServerStream, out grpc.ClientStream) error {
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
	if hdr, err := out.Header(); err == nil && len(hdr) > 0 {
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

// fingerprintFromPeer extracts the SHA-256 fingerprint of the peer's
// leaf cert. Same shape coxswain uses (sha256:<hex-of-PEM>) so coxswain and
// relay agree on the value without sharing code.
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
	errMissingMethod = errors.New("relay: no method in server stream")
	errNoPeer        = errors.New("relay: no peer info on context")
	errNoTLS         = errors.New("relay: peer auth is not TLS")
	errNoClientCert  = errors.New("relay: no client certificate")
)
