// SPDX-License-Identifier: AGPL-3.0-or-later
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
	"sync/atomic"
	"time"

	"github.com/PharosVPN/beacon/relay"
	"github.com/PharosVPN/beacon/tunnel"
	"github.com/spf13/cobra"
)

// defaultConfigDir is where a remote beacon reads its mTLS material.
// helm places it there during relay enrollment (DESIGN §5); until
// that milestone (R5) an operator stages the files by hand.
const defaultConfigDir = "/etc/beacon"

// mTLS material filenames inside the config dir.
const (
	fileDeviceCA = "device-ca.crt" // verifies caravel client certs
	fileFleetCA  = "fleet-ca.crt"  // verifies helm on the tunnel + backend legs
	fileRelayCrt = "relay.crt"     // beacon's Fleet-CA relay cert
	fileRelayKey = "relay.key"     // its private key
)

func newRunCmd() *cobra.Command {
	var clientAddr, tunnelAddr, configDir string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run beacon as a remote relay",
		Long: "Run beacon as a remote relay on a public host.\n\n" +
			"beacon serves caravel clients on --client-addr and waits for the\n" +
			"helm controller to dial IN on --tunnel-addr; helm opens no inbound\n" +
			"ports of its own. Each client RPC is forwarded as a multiplexed\n" +
			"substream back through that one helm-initiated connection.\n\n" +
			"mTLS material is read from --config-dir: device-ca.crt, fleet-ca.crt,\n" +
			"relay.crt and relay.key. Relay enrollment (R5) will issue these over\n" +
			"SSH; for now stage them by hand.\n\n" +
			"To embed a relay in-process instead, helm imports the\n" +
			"github.com/PharosVPN/beacon/relay package — see docs/HELM-INTEGRATION.md.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRemote(cmd.Context(), runOptions{
				clientAddr: clientAddr,
				tunnelAddr: tunnelAddr,
				configDir:  configDir,
			})
		},
	}
	cmd.Flags().StringVar(&clientAddr, "client-addr", ":8443",
		"address to serve caravel mTLS clients on")
	cmd.Flags().StringVar(&tunnelAddr, "tunnel-addr", ":8444",
		"address helm dials in on to establish the reverse tunnel")
	cmd.Flags().StringVar(&configDir, "config-dir", defaultConfigDir,
		"directory holding the relay's mTLS material")
	return cmd
}

type runOptions struct {
	clientAddr string
	tunnelAddr string
	configDir  string
}

// runRemote operates beacon as a remote relay until the context is
// cancelled (SIGINT/SIGTERM).
func runRemote(ctx context.Context, opts runOptions) error {
	logf := func(format string, args ...any) { log.Printf(format, args...) }

	mat, err := loadMaterial(opts.configDir)
	if err != nil {
		return err
	}

	// Tunnel listener: helm dials in here over mTLS. beacon terminates
	// the TLS, then tunnel.AcceptOne wraps the connection as a yamux
	// client session.
	tunnelTLS, err := mat.tunnelServerTLS()
	if err != nil {
		return err
	}
	tcpLis, err := net.Listen("tcp", opts.tunnelAddr)
	if err != nil {
		return fmt.Errorf("listen tunnel %s: %w", opts.tunnelAddr, err)
	}
	defer func() { _ = tcpLis.Close() }()
	tunnelLis := tls.NewListener(tcpLis, tunnelTLS)

	// current holds the live helm tunnel, replaced on every reconnect.
	// nil means no controller is connected.
	var current atomic.Pointer[tunnel.ClientTunnel]
	go acceptTunnels(ctx, tunnelLis, &current, logf)

	r, err := relay.Start(relay.Config{
		ClientListenAddr: opts.clientAddr,
		RelayCertPEM:     mat.relayCert,
		RelayKeyPEM:      mat.relayKey,
		ClientTrustPEM:   mat.deviceCA,
		BackendTrustPEM:  mat.fleetCA,
		BackendDialer: func(dctx context.Context, _ string) (net.Conn, error) {
			ct := current.Load()
			if ct == nil || ct.Closed() {
				return nil, errors.New("beacon: no helm tunnel connected")
			}
			return ct.Open(dctx)
		},
		Logf: logf,
	})
	if err != nil {
		return err
	}
	defer r.Stop()

	logf("[beacon] remote relay ready — caravel clients on %s, helm tunnel on %s",
		r.Addr(), opts.tunnelAddr)
	<-ctx.Done()
	logf("[beacon] shutdown signal received")
	return nil
}

// acceptTunnels accepts helm's reverse-tunnel connections one at a
// time, publishing each as the current tunnel and waiting for it to
// close before accepting the next. v1 is single-controller (DESIGN
// §2; see package tunnel).
func acceptTunnels(
	ctx context.Context,
	lis net.Listener,
	current *atomic.Pointer[tunnel.ClientTunnel],
	logf func(string, ...any),
) {
	const retryPause = time.Second
	for ctx.Err() == nil {
		ct, err := tunnel.AcceptOne(ctx, lis)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logf("[beacon] tunnel accept failed: %v (retrying in %s)", err, retryPause)
			select {
			case <-ctx.Done():
				return
			case <-time.After(retryPause):
			}
			continue
		}
		current.Store(ct)
		logf("[beacon] helm tunnel connected")
		select {
		case <-ctx.Done():
			return
		case <-ct.Done():
			current.Store(nil)
			logf("[beacon] helm tunnel closed — awaiting reconnect")
		}
	}
}

// material is the relay's mTLS material, loaded from the config dir.
type material struct {
	deviceCA  []byte
	fleetCA   []byte
	relayCert []byte
	relayKey  []byte
}

func loadMaterial(dir string) (*material, error) {
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
	m := &material{}
	var err error
	if m.deviceCA, err = read(fileDeviceCA); err != nil {
		return nil, err
	}
	if m.fleetCA, err = read(fileFleetCA); err != nil {
		return nil, err
	}
	if m.relayCert, err = read(fileRelayCrt); err != nil {
		return nil, err
	}
	if m.relayKey, err = read(fileRelayKey); err != nil {
		return nil, err
	}
	return m, nil
}

// tunnelServerTLS is the TLS config for the tunnel listener. beacon
// presents its relay cert; helm must present a Fleet-CA client cert.
func (m *material) tunnelServerTLS() (*tls.Config, error) {
	cert, err := tls.X509KeyPair(m.relayCert, m.relayKey)
	if err != nil {
		return nil, fmt.Errorf("parse relay keypair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(m.fleetCA) {
		return nil, errors.New("fleet-ca.crt not parseable")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
