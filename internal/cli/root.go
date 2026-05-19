// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Package cli wires up the beacon command-line interface — `gen-csr`
// and `run`, which form the helm↔beacon relay-enrolment contract, plus
// `version`. The embedded relay is not a CLI command: helm imports
// github.com/PharosVPN/beacon/relay and runs it in-process (see
// docs/HELM-INTEGRATION.md).
package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

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
		newGenCSRCmd(),
		newRunCmd(),
		newVersionCmd(),
	)
	return root
}

// Execute runs the beacon CLI. The command context is cancelled on
// SIGINT/SIGTERM so `beacon run` shuts down cleanly.
func Execute() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return newRootCmd().ExecuteContext(ctx)
}
