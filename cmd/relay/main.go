// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The PharosVPN Authors

// Command relay is the PharosVPN relay — a stateless, public-facing
// transparent gRPC proxy that lets end-user clients reach a coxswain controller
// that has no public IP and no inbound ports (DESIGN §2, §3).
package main

import (
	"fmt"
	"os"

	"github.com/PharosVPN/relay/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "relay: "+err.Error())
		os.Exit(1)
	}
}
