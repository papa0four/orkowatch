// cmd/commands/cliargs/cliargs.go

// Package cliargs holds the rule for the arguments of a command that takes
// none. It stands apart from cmd/commands and cmd/commands/security so both
// can use it, since the first imports the second.
package cliargs

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// None refuses any argument to cmd. A command with subcommands keeps cobra's
// answer, since a word there names a command that does not exist. Any other
// command calls the word an argument, and when it takes a list flag it says a
// list is one argument: a shell splits a list written with a space after a
// comma, and the name after the space arrives here, where cobra would call it
// an unknown command.
func None(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil
	}
	if cmd.HasSubCommands() {
		return cobra.NoArgs(cmd, args)
	}
	message := fmt.Sprintf("unexpected argument %q to %s", args[0], cmd.CommandPath())
	var lists []string
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Value.Type() == "stringSlice" {
			lists = append(lists, "--"+f.Name)
		}
	})
	if len(lists) > 0 {
		message += "; a list given to " + strings.Join(lists, " or ") + " is one argument, its names joined by commas with no spaces"
	}
	return errors.New(message)
}
