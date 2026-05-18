// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

// Command beacon is the PharosVPN relay — a stateless, public-facing
// transparent gRPC proxy that lets end-user clients reach a helm controller
// that has no public IP and no inbound ports (DESIGN §2, §3).
package main

import (
	"fmt"
	"os"

	"github.com/PharosVPN/beacon/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "beacon: "+err.Error())
		os.Exit(1)
	}
}
