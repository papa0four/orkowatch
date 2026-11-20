// cmd/commands/inventory.go

package cmd

import (
	"fmt"
	"slices"
	"time"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/cmd/commands/delivery"
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
	module := modules[at]

	var out *delivery.Flags
	cmd := &cobra.Command{
		Use:     m.use,
		Args:    cobra.NoArgs,
		Short:   m.short,
		Long:    m.long,
		Example: m.example,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := out.Resolve(cmd); err != nil {
				return err
			}
			started := time.Now()
			result := &ScanResult{Timestamp: started, Errors: make([]string, 0)}
			module.collect(cmd.Context(), result)
			if ran := result.Modules[len(result.Modules)-1]; ran.Result == finding.ResultError {
				return fmt.Errorf("%s: %s", m.use, ran.Reason)
			}
			result.Duration = time.Since(started)
			return out.Deliver(allReport{title: "owatch " + m.use, result: result}, module.mask)
		},
	}
	out = delivery.Bind(cmd)
	return cmd
}
