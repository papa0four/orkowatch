// cmd/commands/software.go

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/internal/selection"
)

// newSoftwareCmd returns the command that lists installed software.
func newSoftwareCmd() *cobra.Command {
	return newInventoryCmd(standaloneModule{
		use:   selection.NameSoftware,
		short: "List installed software on the host",
		long: `The software command gathers and lists the installed software packages from the host operating system, including version details where available.

On AlmaLinux, Alpine, Red Hat Enterprise Linux, Rocky Linux, and Ubuntu, the
packages are then matched against the host's OSV dataset, which owatch data
refresh fetches, and the report gains a Vulnerabilities section: each CVE with a
fix available, the unfixed counted by package, and what could not be matched.
With no dataset held, the section says matching was not done and what to run.

The report opens in the results browser on a terminal, with the same layout as an audit.`,
		example: `  # Open the installed software in the results browser
  owatch software

  # Print it as text instead of opening the results browser
  owatch software --plain

  # Save it to a directory in YAML format
  owatch software -o yaml --report-file /path/to/reports`,
	})
}
