// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Package cli wires up the relay command-line interface — `gen-csr`
// and `run`, which form the coxswain↔relay relay-enrolment contract, plus
// `version`. The embedded relay is not a CLI command: coxswain imports
// github.com/PharosVPN/relay/relay and runs it in-process (see
// docs/COXSWAIN-INTEGRATION.md).
package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

// version is the relay build version. Overridable at link time with
// -ldflags "-X github.com/PharosVPN/relay/internal/cli.version=...".
var version = "0.1.0-dev"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "relay",
		Short: "PharosVPN relay",
		Long: "relay — the PharosVPN relay.\n\n" +
			"relay is a stateless, public-facing transparent gRPC proxy. It\n" +
			"terminates client mTLS and forwards opaque gRPC streams to a coxswain\n" +
			"controller that has no public IP and no inbound ports. It holds no\n" +
			"database and makes no policy decisions — coxswain does all of that.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newGenCSRCmd(),
		newRunCmd(),
		newEgressCmd(),
		newOnionKeyCmd(),
		newOnionCmd(),
		newVersionCmd(),
	)
	return root
}

// Execute runs the relay CLI. The command context is cancelled on
// SIGINT/SIGTERM so `relay run` shuts down cleanly.
func Execute() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return newRootCmd().ExecuteContext(ctx)
}
