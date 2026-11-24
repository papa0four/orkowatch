// cmd/commands/cliargs/cliargs_test.go

package cliargs

import (
	"os"
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

	// A name that is also a path here, as a directory audit is to scan can
	// be, stays the path; after a trailing comma it is still the list's.
	t.Chdir(t.TempDir())
	if err := os.Mkdir("users", 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ args, want []string }{
		{[]string{"audit", "--skip-checks", "ssh", "users"}, []string{"audit", "--skip-checks", "ssh", "users"}},
		{[]string{"audit", "--skip-checks", "ssh,", "users"}, []string{"audit", "--skip-checks", "ssh,users"}},
	} {
		if got := Rejoin(root, tt.args); !slices.Equal(got, tt.want) {
			t.Errorf("beside a directory named users, Rejoin(%q) = %q, want %q", tt.args, got, tt.want)
		}
	}
}

// No argument passes. A stray one is called an argument, whatever flags the
// command takes; a command with subcommands keeps cobra's unknown command.
func TestNone(t *testing.T) {
	root := &cobra.Command{Use: "owatch"}
	leaf := &cobra.Command{Use: "audit", RunE: func(*cobra.Command, []string) error { return nil }}
	plain := &cobra.Command{Use: "version", RunE: func(*cobra.Command, []string) error { return nil }}
	parent := &cobra.Command{Use: "data"}
	parent.AddCommand(&cobra.Command{Use: "status"})
	var skip []string
	NameList(leaf, &skip, "skip-checks", "", []string{"ssh"})
	root.AddCommand(leaf, plain, parent)

	if err := None(leaf, nil); err != nil {
		t.Errorf("no argument gave %v", err)
	}
	for cmd, want := range map[*cobra.Command]string{
		leaf:   `unexpected argument "permissions" to owatch audit`,
		plain:  `unexpected argument "permissions" to owatch version`,
		parent: `unknown command "permissions" for "owatch data"`,
	} {
		if err := None(cmd, []string{"permissions"}); err == nil || err.Error() != want {
			t.Errorf("%s gave %v, want %s", cmd.Name(), err, want)
		}
	}
}
