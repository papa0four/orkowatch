// cmd/commands/root_test.go

package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// takesArguments are the commands with no subcommands that take an argument.
// Every other one refuses a stray argument as an argument, by the rule the
// commands share, so a word a shell split from a list is not reported as an
// unknown command.
var takesArguments = map[string]bool{
	"owatch browse":      true,
	"owatch data import": true,
	"owatch data remove": true,
}

func TestEveryCommandRefusesAStrayArgument(t *testing.T) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			walk(sub)
		}
		path := c.CommandPath()
		if c.HasSubCommands() || takesArguments[path] || c.Name() == "help" || c.Name() == "completion" {
			return
		}
		if c.Args == nil {
			t.Errorf("%s states no rule for its arguments", path)
			return
		}
		want := `unexpected argument "stray" to ` + path
		if err := c.Args(c, []string{"stray"}); err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("%s refused a stray argument with %v, want %s", path, err, want)
		}
	}
	root := newRootCmd()
	root.InitDefaultHelpCmd()
	walk(root)
}
