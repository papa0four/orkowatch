// cmd/commands/inventory.go

package cmd

import (
	"fmt"
	"slices"
	"time"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/cmd/commands/cliargs"
	"github.com/papa0four/orkowatch/cmd/commands/delivery"
	"github.com/papa0four/orkowatch/cmd/commands/held"
	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/security/finding"
)

// standaloneModule describes an inventory module as a command of its own:
// the module's name, which is what the command is called, and what the
// command says. The module itself, the mask that names its report file and
// the function that runs it, is the entry of that name in inventoryModules.
type standaloneModule struct {
	use     string
	short   string
	long    string
	example string
}

// newInventoryCmd builds the command for a module that runs alone. It has the
// output surface of all, so a run of one module is delivered like a run of
// several: the results browser on a terminal, the report in the format named
// with -o to a pipe or with --plain, and a named file with --report-file.
// Its report is an all report holding that one module, which owatch browse
// already opens, so nothing about reading it back is specific to the module.
func newInventoryCmd(m standaloneModule) *cobra.Command {
	modules := inventoryModules()
	at := slices.IndexFunc(modules, func(module inventory) bool { return module.name == m.use })
	if at < 0 {
		panic("cmd: no inventory module is named " + m.use)
	}
	return newModuleCmd(m, modules[at], m.use, held.ForHost, atTerminal)
}

// atTerminal reports whether a person is at the terminal to answer a
// question: the command's input and output are both a terminal.
func atTerminal() bool {
	return render.StdinIsTerminal() && render.StdoutIsTerminal()
}

// newModuleCmd builds the command that runs module alone and delivers its
// report as all would deliver a report of that one module. name is how the
// command is invoked after owatch, which titles the report and prefixes an
// error, data gives the run the module reads datasets through, and
// interactive reports whether a person is there to answer the question asked
// before a module that reads datasets runs without them. owatch data status
// is built here with a module all does not run.
func newModuleCmd(m standaloneModule, module inventory, name string, data func() *held.Run, interactive func() bool) *cobra.Command {
	var out *delivery.Flags
	cmd := &cobra.Command{
		Use:     m.use,
		Args:    cliargs.None,
		Short:   m.short,
		Long:    m.long,
		Example: m.example,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := out.Resolve(cmd); err != nil {
				return err
			}
			run := data()
			if err := run.Ask(cmd.Context(), module.reads, interactive(), cmd.InOrStdin(), cmd.ErrOrStderr()); err != nil {
				return err
			}
			started := time.Now()
			result := &ScanResult{Timestamp: started, Errors: make([]string, 0)}
			module.collect(cmd.Context(), run, result)
			result.Operator = run.Operator()
			if ran := result.Modules[len(result.Modules)-1]; ran.Result == finding.ResultError {
				return fmt.Errorf("%s: %s", name, ran.Reason)
			}
			result.Duration = time.Since(started)
			return out.Deliver(allReport{title: "owatch " + name, result: result}, module.mask)
		},
	}
	out = delivery.Bind(cmd)
	return cmd
}
