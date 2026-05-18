// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 The PharosVPN Authors

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newVersionCmd prints the relay version to stdout. helm records the
// installed relay version after an SSH install or update (DESIGN §5).
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the beacon relay version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), version)
			return err
		},
	}
}
