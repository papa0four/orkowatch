// cmd/commands/osinfo.go

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/internal/selection"
)

// newOsinfoCmd returns the command that gathers the OS fingerprint.
func newOsinfoCmd() *cobra.Command {
	return newInventoryCmd(standaloneModule{
		use:   selection.NameOS,
		short: "Gather OS Fingerprint information",
		long: `osinfo will scan the host machine and retrieve basic OS fingerprint information such as platform, version, and kernel details.

The Target line names this host as owatch data refresh --for takes it, to fetch
on another host the datasets this one needs.

The report opens in the results browser on a terminal, with the same layout as an audit.`,
		example: `  # Open the OS fingerprint in the results browser
  owatch osinfo

  # Print it as text instead of opening the results browser
  owatch osinfo --plain

  # Save it to a directory in JSON format
  owatch osinfo -o json --report-file /path/to/reports`,
	})
}
