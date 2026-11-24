// cmd/commands/cliargs/cliargs_test.go

package cliargs

import (
	"slices"
	"testing"

	"github.com/spf13/cobra"
)

// A word a shell split off a list goes back into it when the list ended in a
// comma or the word holds only names the flag accepts; a path, a word after
// another flag, and anything after -- stay where they are. The command is
// found from the root or given directly.
func TestRejoin(t *testing.T) {
	root := &cobra.Command{Use: "owatch"}
	audit := &cobra.Command{Use: "audit", RunE: func(*cobra.Command, []string) error { return nil }}
	var skip []string
	NameList(audit, &skip, "skip-checks", "", []string{"firewall", "fwall", "ssh", "users"})
	audit.Flags().Bool("ssh", false, "")
	root.AddCommand(audit)

	for _, tt := range []struct{ args, want []string }{
		{[]string{"audit", "--skip-checks", "ssh", "users"}, []string{"audit", "--skip-checks", "ssh,users"}},
		{[]string{"audit", "--skip-checks", "ssh", "USERS", "fwall"}, []string{"audit", "--skip-checks", "ssh,USERS,fwall"}},
		{[]string{"audit", "--skip-checks", "ssh,", "users"}, []string{"audit", "--skip-checks", "ssh,users"}},
		{[]string{"audit", "--skip-checks", "ssh,", "userz"}, []string{"audit", "--skip-checks", "ssh,userz"}},
		{[]string{"audit", "--skip-checks=ssh", "users,firewall"}, []string{"audit", "--skip-checks=ssh,users,firewall"}},
		{[]string{"audit", "--skip-checks", "ssh", "/dir"}, []string{"audit", "--skip-checks", "ssh", "/dir"}},
		{[]string{"audit", "--skip-checks", "ssh", "--ssh", "users"}, []string{"audit", "--skip-checks", "ssh", "--ssh", "users"}},
		{[]string{"audit", "--", "--skip-checks", "ssh", "users"}, []string{"audit", "--", "--skip-checks", "ssh", "users"}},
		{[]string{"audit", "--skip-checks"}, []string{"audit", "--skip-checks"}},
	} {
		if got := Rejoin(root, tt.args); !slices.Equal(got, tt.want) {
			t.Errorf("Rejoin(%q) = %q, want %q", tt.args, got, tt.want)
		}
	}
	if got := Rejoin(audit, []string{"--skip-checks", "ssh", "users"}); !slices.Equal(got, []string{"--skip-checks", "ssh,users"}) {
		t.Errorf("Rejoin on the command itself = %q", got)
	}
}

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
