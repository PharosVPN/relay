// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"fmt"
	"path/filepath"

	"github.com/PharosVPN/beacon/internal/pki"
	"github.com/spf13/cobra"
)

// newGenCSRCmd generates the relay's mTLS keypair on the host and
// prints a PEM-encoded certificate signing request to stdout.
//
// This is the first step of SSH enrolment (DESIGN §5, decision 14):
// helm runs `beacon gen-csr` over SSH, captures the CSR from stdout,
// signs it with the Fleet CA, and pushes relay.crt, fleet-ca.crt and
// device-ca.crt back. The relay's private key is written to relay.key
// and never leaves the host.
//
// Re-running gen-csr is idempotent — an existing key is reused.
func newGenCSRCmd() *cobra.Command {
	var configDir string

	cmd := &cobra.Command{
		Use:   "gen-csr",
		Short: "Generate the relay keypair and print a CSR for helm to sign",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			keyPath := filepath.Join(configDir, fileRelayKey)
			res, err := pki.GenerateCSR(keyPath)
			if err != nil {
				return err
			}

			// Diagnostics go to stderr; stdout carries only the CSR so
			// helm can capture it cleanly over SSH. A failed diagnostic
			// write must not fail gen-csr itself.
			if res.KeyGenerated {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "beacon: generated relay key at %s\n", keyPath)
			} else {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "beacon: reusing existing relay key at %s\n", keyPath)
			}
			_, err = cmd.OutOrStdout().Write(res.CSRPEM)
			return err
		},
	}
	cmd.Flags().StringVar(&configDir, "config-dir", defaultConfigDir,
		"directory the relay keypair is written to")
	return cmd
}
