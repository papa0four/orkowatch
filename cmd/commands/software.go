// cmd/commands/software.go

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/internal/softwarelist"
)

// newSoftwareCmd returns the command that lists installed software
func newSoftwareCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "software",
		Args:  cobra.NoArgs,
		Short: "List installed software on the host",
		Long:  `The software command gathers and lists the installed software packages from the host operating system, including version details where available.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := softwarelist.GetInstalledSoftwareList(cmd.Context())
			if err != nil {
				return fmt.Errorf("software: %w", err)
			}
			if err := softwarelist.WriteText(cmd.OutOrStdout(), softwarelist.View(entries)); err != nil {
				return fmt.Errorf("failed to write message: %w", err)
			}
			return nil
		},
	}
}
