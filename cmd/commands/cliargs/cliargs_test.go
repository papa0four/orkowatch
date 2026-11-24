// cmd/commands/cliargs/cliargs_test.go

package cliargs

import (
	"testing"

	"github.com/spf13/cobra"
)

// No argument passes. A stray one is called an argument, with the list flags
// the command takes named; a command with subcommands keeps cobra's unknown
// command.
func TestNone(t *testing.T) {
	root := &cobra.Command{Use: "owatch"}
	leaf := &cobra.Command{Use: "audit", RunE: func(*cobra.Command, []string) error { return nil }}
	plain := &cobra.Command{Use: "version", RunE: func(*cobra.Command, []string) error { return nil }}
	parent := &cobra.Command{Use: "data"}
	parent.AddCommand(&cobra.Command{Use: "status"})
	leaf.Flags().StringSlice("skip-checks", nil, "")
	leaf.Flags().StringSlice("skip-modules", nil, "")
	leaf.Flags().Bool("yes", false, "")
	root.AddCommand(leaf, plain, parent)

	if err := None(leaf, nil); err != nil {
		t.Errorf("no argument gave %v", err)
	}
	for cmd, want := range map[*cobra.Command]string{
		leaf:   `unexpected argument "permissions" to owatch audit; a list given to --skip-checks or --skip-modules is one argument, its names joined by commas with no spaces`,
		plain:  `unexpected argument "permissions" to owatch version`,
		parent: `unknown command "permissions" for "owatch data"`,
	} {
		if err := None(cmd, []string{"permissions"}); err == nil || err.Error() != want {
			t.Errorf("%s gave %v, want %s", cmd.Name(), err, want)
		}
	}
}
