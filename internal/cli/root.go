// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Package cli wires up the beacon command-line interface. The relay's
// transport commands (embedded mode, remote reverse-tunnel mode) land in
// later milestones once the beacon↔helm wire contract is published in
// docs/proto/; for now the CLI exposes only `version`.
package cli

import "github.com/spf13/cobra"

// version is the beacon build version. Overridable at link time with
// -ldflags "-X github.com/PharosVPN/beacon/internal/cli.version=...".
var version = "0.1.0-dev"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "beacon",
		Short: "PharosVPN relay",
		Long: "beacon — the PharosVPN relay.\n\n" +
			"beacon is a stateless, public-facing transparent gRPC proxy. It\n" +
			"terminates client mTLS and forwards opaque gRPC streams to a helm\n" +
			"controller that has no public IP and no inbound ports. It holds no\n" +
			"database and makes no policy decisions — helm does all of that.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newVersionCmd(),
	)
	return root
}

// Execute runs the beacon CLI.
func Execute() error {
	return newRootCmd().Execute()
}
