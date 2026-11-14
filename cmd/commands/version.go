// cmd/commands/version.go

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

/*
Version is the current application version.
It defaults to the active development stage and is overridden
at build time via -ldflags "-X github.com/papa0four/orkowatch/cmd/commands.Version=..."
*/
var Version = "dev"

// newVersionCmd returns the command that prints the application version
// mathcing the --version output
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Args:  cobra.NoArgs,
		Short: "Print the orkowatch version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("owatch version %s\n", Version)
		},
	}
}
