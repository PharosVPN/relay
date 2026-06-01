// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/PharosVPN/beacon/egress"
	"github.com/spf13/cobra"
)

func newEgressCmd() *cobra.Command {
	var tunnelAddr, configDir string
	cmd := &cobra.Command{
		Use:   "egress",
		Short: "Run beacon as a control-plane egress relay",
		Long: "Run beacon as a control-plane egress relay (DESIGN §3, decision 19).\n\n" +
			"coxswain dials IN on --tunnel-addr and opens one substream per outbound\n" +
			"connection to a node; each substream carries a CONNECT target (a node\n" +
			"host:port) that beacon dials over raw TCP and pipes. The node — and any\n" +
			"observer watching it — sees beacon's IP, never coxswain's.\n\n" +
			"beacon is protocol-blind here: the gRPC-mTLS or SSH payload riding the\n" +
			"substream is end-to-end secured between coxswain and the node, so a\n" +
			"compromised relay learns only 'coxswain reached node:port', never the\n" +
			"contents. One generic relay therefore serves both control channels.\n\n" +
			"mTLS material is read from --config-dir: fleet-ca.crt (verifies coxswain),\n" +
			"relay.crt and relay.key (beacon's identity) — the same files as `run`,\n" +
			"minus device-ca.crt (this leg carries no caravel clients).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEgress(cmd.Context(), tunnelAddr, configDir)
		},
	}
	cmd.Flags().StringVar(&tunnelAddr, "tunnel-addr", ":8456",
		"address coxswain dials in on to establish the egress tunnel")
	cmd.Flags().StringVar(&configDir, "config-dir", defaultConfigDir,
		"directory holding the relay's mTLS material")
	return cmd
}

// runEgress operates beacon as a control-plane egress relay until the context
// is cancelled (SIGINT/SIGTERM).
func runEgress(ctx context.Context, tunnelAddr, configDir string) error {
	logf := func(format string, args ...any) { log.Printf(format, args...) }

	tunnelTLS, err := egressTunnelTLS(configDir)
	if err != nil {
		return err
	}
	tcpLis, err := net.Listen("tcp", tunnelAddr)
	if err != nil {
		return fmt.Errorf("listen tunnel %s: %w", tunnelAddr, err)
	}
	defer func() { _ = tcpLis.Close() }()
	tunnelLis := tls.NewListener(tcpLis, tunnelTLS)

	// nodeDial is how the relay reaches a node once coxswain hands it a CONNECT
	// target. Plain TCP — the payload is already end-to-end secured.
	nodeDial := func(dctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 15 * time.Second}).DialContext(dctx, network, address)
	}

	logf("[beacon] egress relay ready — coxswain egress tunnel on %s", tunnelAddr)
	return egress.RunRelay(ctx, tunnelLis, nodeDial, logf)
}

// egressTunnelTLS builds the egress tunnel listener TLS: beacon presents its
// relay cert; coxswain must present a Fleet-CA client cert. Mirrors run's
// tunnelServerTLS, but needs no device-ca (no caravel clients on this leg).
func egressTunnelTLS(dir string) (*tls.Config, error) {
	read := func(name string) ([]byte, error) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("read relay material: %w", err)
		}
		if len(b) == 0 {
			return nil, fmt.Errorf("read relay material: %s is empty", name)
		}
		return b, nil
	}
	relayCert, err := read(fileRelayCrt)
	if err != nil {
		return nil, err
	}
	relayKey, err := read(fileRelayKey)
	if err != nil {
		return nil, err
	}
	fleetCA, err := read(fileFleetCA)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(relayCert, relayKey)
	if err != nil {
		return nil, fmt.Errorf("parse relay keypair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(fleetCA) {
		return nil, errors.New("fleet-ca.crt not parseable")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
