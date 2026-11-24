// cmd/commands/cliargs/cliargs.go

// Package cliargs holds how the owatch commands read their command line: the
// flags that take a list of names, putting back a name a shell split off such
// a list, and refusing arguments where a command takes none. It stands apart
// from cmd/commands and cmd/commands/security so both can use it, since the
// first imports the second.
package cliargs

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

// namesKey is the annotation under which a list flag records the names it
// accepts.
const namesKey = "owatch-names"

// NameList defines on cmd a flag that takes a comma-separated list of names
// into p, and records the names it accepts, so Rejoin can tell a name a shell
// split off the list from an argument.
func NameList(cmd *cobra.Command, p *[]string, name, usage string, names []string) {
	cmd.Flags().StringSliceVar(p, name, []string{}, usage)
	if err := cmd.Flags().SetAnnotation(name, namesKey, names); err != nil {
		panic("cliargs: " + err.Error())
	}
}

// Rejoin returns args with each word a shell split off a list flag's value
// put back into that list. A word joins the list it directly follows when the
// list ends in a comma, as "ssh, users" written without quotes leaves it, or
// when every name in it is one the flag accepts, as a shell that splits a
// list on its commas leaves "ssh,users". Any other word, a path among them,
// stays an argument. The command the words are for is found from cmd and
// args as cobra finds it.
func Rejoin(cmd *cobra.Command, args []string) []string {
	target, _, err := cmd.Find(args)
	if err != nil {
		target = cmd
	}
	out := make([]string, 0, len(args))
	var names []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if last := len(out) - 1; names != nil && continues(out[last], arg, names) {
			if !strings.HasSuffix(out[last], ",") {
				out[last] += ","
			}
			out[last] += arg
			continue
		}
		names = nil
		out = append(out, arg)
		if arg == "--" {
			return append(out, args[i+1:]...)
		}
		flag, _, inline := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		if !strings.HasPrefix(arg, "--") {
			continue
		}
		f := target.Flags().Lookup(flag)
		if f == nil || f.Annotations[namesKey] == nil {
			continue
		}
		if !inline {
			if i+1 == len(args) {
				continue
			}
			i++
			out = append(out, args[i])
		}
		names = f.Annotations[namesKey]
	}
	return out
}

// continues reports whether word goes on the list whose value ends last: the
// value ends in a comma, or every name in word is one of names.
func continues(last, word string, names []string) bool {
	if strings.HasPrefix(word, "-") {
		return false
	}
	if strings.HasSuffix(last, ",") {
		return true
	}
	found := false
	for _, part := range strings.Split(word, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		if !slices.Contains(names, part) {
			return false
		}
		found = true
	}
	return found
}

// None refuses any argument to cmd. A command with subcommands keeps cobra's
// answer, since a word there names a command that does not exist. Any other
// command calls the word an argument, where cobra would call it an unknown
// command. A name a shell split off a list never arrives here, since Rejoin
// puts it back first.
func None(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil
	}
	if cmd.HasSubCommands() {
		return cobra.NoArgs(cmd, args)
	}
	return fmt.Errorf("unexpected argument %q to %s", args[0], cmd.CommandPath())
}
