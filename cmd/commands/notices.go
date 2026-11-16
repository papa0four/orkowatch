// cmd/commands/notices.go

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/internal/notices"
)

// newNoticesCmd returns the command that prints the third-party notices
// embedded in the binary.
func newNoticesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "notices",
		Args:  cobra.NoArgs,
		Short: "Print the third-party notices for data bundled in owatch",
		Long: `Print the license notices that MITRE's terms require for the MITRE ATT&CK® and
CWE™ content owatch carries. The same text is embedded in the binary, so every
copy of owatch has it.`,
		Example: `  # Print the notices
  owatch notices`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := fmt.Fprint(cmd.OutOrStdout(), notices.Text()); err != nil {
				return fmt.Errorf("print notices: %w", err)
			}
			return nil
		},
	}
}
