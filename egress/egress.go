// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package egress is the control-plane egress relay protocol (DESIGN §3,
// decision 19). It lets coxswain reach a node without the node ever seeing
// coxswain's IP: coxswain opens a substream on its outbound tunnel to a relay,
// writes a one-line CONNECT target, and the relay dials that target over raw
// TCP and pumps bytes both ways.
//
// The relay is deliberately protocol-blind. The coxswain↔node payload riding
// the substream is already end-to-end secured — gRPC mTLS on :8444, or SSH on
// :22 — so the relay terminates neither and interprets nothing past the target
// line. One generic relay therefore serves both control channels, and a
// compromised relay host learns only "coxswain talked to node:port", never the
// contents.
//
// This is the inverse of the beacon ingress proxy (package relay): there the
// relay opens substreams toward coxswain; here coxswain opens substreams toward
// the relay. coxswain stays the dialer in both, so it keeps zero inbound.
package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// maxTargetLen bounds the CONNECT target line so a misbehaving or hostile peer
// cannot make the relay buffer without limit while scanning for the newline.
const maxTargetLen = 255

// Dialer dials the relayed target. It matches net.Dialer.DialContext, so the
// production relay passes a (&net.Dialer{Timeout: …}).DialContext and tests
// substitute an in-memory dialer.
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// StreamOpener is coxswain's handle to its outbound tunnel: each call returns a
// fresh substream to the relay. It is satisfied by the egress tunnel's yamux
// session (and by a net.Pipe-backed fake in tests).
type StreamOpener interface {
	OpenStream(ctx context.Context) (net.Conn, error)
}

// Open dials addr through the relay reachable over t. It opens a substream,
// writes the CONNECT target, and returns the substream as a net.Conn whose
// payload is piped verbatim to addr. The caller layers its own transport
// security (gRPC mTLS / SSH) on top — Open adds none.
func Open(ctx context.Context, t StreamOpener, addr string) (net.Conn, error) {
	if err := validateTarget(addr); err != nil {
		return nil, err
	}
	stream, err := t.OpenStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("egress: open substream: %w", err)
	}
	if err := writeTarget(stream, addr); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("egress: write target: %w", err)
	}
	return stream, nil
}

// Serve handles one accepted substream on the relay: it reads the CONNECT
// target, dials it with dial, and pumps bytes in both directions until either
// side closes. It always closes stream before returning.
func Serve(ctx context.Context, stream net.Conn, dial Dialer) error {
	defer stream.Close()

	addr, err := readTarget(stream)
	if err != nil {
		return fmt.Errorf("egress: read target: %w", err)
	}
	backend, err := dial(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("egress: dial %s: %w", addr, err)
	}
	pump(stream, backend)
	return nil
}

// pump copies bytes both ways between a and b. When either direction reaches
// EOF (or errors), both conns are closed so the other copy unblocks. This is
// the right teardown for the channels we carry: gRPC and SSH are bidirectional
// for the life of the connection, so when one half ends the connection is over.
func pump(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	<-done
	_ = a.Close()
	_ = b.Close()
	<-done
}

// writeTarget emits the one-line CONNECT preamble: "host:port\n".
func writeTarget(w io.Writer, addr string) error {
	_, err := io.WriteString(w, addr+"\n")
	return err
}

// readTarget reads the CONNECT preamble one byte at a time up to the newline,
// so it never consumes the tunneled payload that follows. The target is bounded
// and validated as host:port.
func readTarget(r io.Reader) (string, error) {
	buf := make([]byte, 0, 64)
	one := make([]byte, 1)
	for len(buf) <= maxTargetLen {
		n, err := r.Read(one)
		if n == 1 {
			if one[0] == '\n' {
				addr := string(buf)
				if verr := validateTarget(addr); verr != nil {
					return "", verr
				}
				return addr, nil
			}
			buf = append(buf, one[0])
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", errors.New("egress: stream closed before target line")
			}
			return "", err
		}
	}
	return "", fmt.Errorf("egress: target line exceeds %d bytes", maxTargetLen)
}

// validateTarget rejects anything that is not a well-formed host:port. The
// relay only ever dials operator-enrolled nodes, but this keeps a malformed or
// hostile target from reaching net.Dial.
func validateTarget(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("egress: invalid target %q: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("egress: target %q has empty host", addr)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("egress: target %q has invalid port", addr)
	}
	return nil
}
