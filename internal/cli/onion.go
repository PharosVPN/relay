// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"context"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"time"

	"github.com/PharosVPN/relay/onion"
	"github.com/spf13/cobra"
)

func newOnionCmd() *cobra.Command {
	var listenAddr, configDir string
	cmd := &cobra.Command{
		Use:   "onion",
		Short: "Run relay as a control-plane onion relay",
		Long: "Run relay as a control-plane onion-routing hop (DESIGN §3, decision\n" +
			"20). It peels its own layer of each circuit with its onion key, forwards\n" +
			"to the next hop, and pumps the layered stream — learning only its\n" +
			"neighbours, never coxswain's identity or the rest of the path.\n\n" +
			"The listener is plain TCP: the onion supplies confidentiality (setup\n" +
			"sealed to each relay's key, data layered), and a connection whose setup\n" +
			"was not sealed to this relay is dropped. Run `relay onion-key` first to\n" +
			"mint onion.key in --config-dir.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runOnion(cmd.Context(), listenAddr, configDir)
		},
	}
	cmd.Flags().StringVar(&listenAddr, "listen", ":8457",
		"address coxswain and upstream relays dial for the onion circuit")
	cmd.Flags().StringVar(&configDir, "config-dir", defaultConfigDir,
		"directory holding onion.key")
	return cmd
}

func runOnion(ctx context.Context, listenAddr, configDir string) error {
	logf := func(format string, args ...any) { log.Printf(format, args...) }

	priv, _, err := onion.LoadOrCreateKey(filepath.Join(configDir, fileOnionKey))
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen onion %s: %w", listenAddr, err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	// The next hop (relay or node) is reached over plain TCP.
	dial := func(dctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 15 * time.Second}).DialContext(dctx, network, address)
	}

	logf("[relay] onion relay ready on %s", listenAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("onion accept: %w", err)
		}
		go func(c net.Conn) { _ = onion.Serve(ctx, c, priv, dial) }(conn)
	}
}
