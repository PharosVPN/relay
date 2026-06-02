// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"fmt"
	"path/filepath"

	"github.com/PharosVPN/beacon/onion"
	"github.com/spf13/cobra"
)

// fileOnionKey is the relay's persistent X25519 onion key (decision 20),
// alongside the mTLS material in the config dir.
const fileOnionKey = "onion.key"

// newOnionKeyCmd generates (or reuses) the relay's onion keypair on the host and
// prints its base64 X25519 public key to stdout.
//
// Part of SSH enrolment for control-plane onion routing (DESIGN §3, decision
// 20): coxswain runs `beacon onion-key` over SSH, captures the public key, and
// records it on the relay so it can seal onion layers to this hop. The private
// key is written to onion.key and never leaves the host. Idempotent.
func newOnionKeyCmd() *cobra.Command {
	var configDir string
	cmd := &cobra.Command{
		Use:   "onion-key",
		Short: "Generate the relay's onion key and print its public key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			keyPath := filepath.Join(configDir, fileOnionKey)
			priv, created, err := onion.LoadOrCreateKey(keyPath)
			if err != nil {
				return err
			}
			// Diagnostics to stderr; stdout carries only the public key so
			// coxswain can capture it cleanly over SSH.
			if created {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "beacon: generated onion key at %s\n", keyPath)
			} else {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "beacon: reusing existing onion key at %s\n", keyPath)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), onion.PublicKeyBase64(priv.PublicKey()))
			return err
		},
	}
	cmd.Flags().StringVar(&configDir, "config-dir", defaultConfigDir,
		"directory the onion key is written to")
	return cmd
}
