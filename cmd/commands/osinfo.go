// cmd/commands/osinfo.go

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

// newOsinfoCmd returns the command that gather OS fingerprint information
func newOsinfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "osinfo",
		Args:  cobra.NoArgs,
		Short: "Gather OS Fingerprint information",
		Long:  `osinfo will scan the host machine and retrieve basic OS fingerprint information such as platform, version, and kernel details.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			info, err := osfingerprint.GetOSFingerprint()
			if err != nil {
				return fmt.Errorf("osinfo: %w", err)
			}
			return osfingerprint.WriteText(cmd.OutOrStdout(), info)
		},
	}
}
