// cmd/commands/inventory.go

package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/cmd/commands/delivery"
	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/selection"
)

// standaloneModule describes one of the two modules that run as a command of
// their own as well as inside all: what the command is called and says, the
// mask that names its report file, and the function that runs it.
type standaloneModule struct {
	use     string
	short   string
	long    string
	example string
	mask    selection.CheckMask
	collect func(ctx context.Context, result *ScanResult)
}

// newInventoryCmd builds the command for a module that runs alone. It has the
// output surface of all, so a run of one module is delivered like a run of
// several: the results browser on a terminal, the report in the format named
// with -o to a pipe or with --plain, and a named file with --report-file.
// Its report is an all report holding that one module, which owatch browse
// already opens, so nothing about reading it back is specific to the module.
func newInventoryCmd(m standaloneModule) *cobra.Command {
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
			m.collect(cmd.Context(), result)
			if ran := result.Modules[len(result.Modules)-1]; ran.Result == finding.ResultError {
				return fmt.Errorf("%s: %s", m.use, ran.Reason)
			}
			result.Duration = time.Since(started)
			return out.Deliver(allReport{title: "owatch " + m.use, result: result}, m.mask)
		},
	}
	out = delivery.Bind(cmd)
	return cmd
}
