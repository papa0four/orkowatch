// cmd/commands/data.go

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/cmd/commands/cliargs"
	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/epss"
	"github.com/papa0four/orkowatch/internal/dataset/kev"
	"github.com/papa0four/orkowatch/internal/dataset/store"
	"github.com/papa0four/orkowatch/internal/elevation"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/selection"
)

// dataCmd is what the owatch data commands read from the host, held apart so
// a test can give each its own: the datasets owatch knows, the store, the
// host's identity, the time, whether a person is at the terminal to ask,
// whether the process is elevated, and what fetches a dataset.
type dataCmd struct {
	known       []dataset.Dataset
	open        func(context.Context) (store.Store, error)
	host        func() (*osfingerprint.OSInfo, error)
	now         func() time.Time
	interactive func() bool
	in          io.Reader
	elevated    func() bool
	fetcher     func() (fetcher, error)
}

// knownDatasets lists the datasets this version of owatch knows. A source is
// added here as a type that satisfies dataset.Dataset; the commands and the
// store read every source through that interface and name none. They are
// listed in name order, which is the order status shows them in.
func knownDatasets() []dataset.Dataset {
	return []dataset.Dataset{epss.Scores{}, kev.Catalog{}}
}

// newDataCmd returns the owatch data command and its subcommands, reading the
// host itself.
func newDataCmd() *cobra.Command {
	return dataCommand(&dataCmd{
		known:       knownDatasets(),
		open:        store.ForProcess,
		host:        osfingerprint.GetOSFingerprint,
		now:         time.Now,
		interactive: func() bool { return render.StdinIsTerminal() && render.StdoutIsTerminal() },
		in:          os.Stdin,
		elevated:    elevation.Elevated,
		fetcher:     newFetcher,
	})
}

// dataCommand builds the owatch data command over d.
func dataCommand(d *dataCmd) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "data",
		Short: "Manage the vulnerability datasets held on this host",
		Long: `Manage the vulnerability datasets owatch holds on this host, which it reads
with no network. Each account has its own store, at a fixed place under the
account's home. A run as root or from an elevated terminal has no store yet.
Only owatch data refresh opens a network connection.`,
		Args: cliargs.None,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := cmd.Help(); err != nil {
				return fmt.Errorf("displaying help: %w", err)
			}
			return errors.New("owatch data requires a subcommand (import, refresh, remove, status)")
		},
	}
	cmd.AddCommand(d.importCmd(), d.refreshCmd(), d.removeCmd(), d.statusCmd())
	return cmd
}

// statusCmd returns owatch data status, which is delivered as the report of
// one module is.
func (d *dataCmd) statusCmd() *cobra.Command {
	return newModuleCmd(standaloneModule{
		use:   "status",
		short: "Show the datasets held, how old they are, and what needs attention",
		long: `List each dataset that applies to this host, held or not, with the date of
its data, when it was fetched, its size, and its state: current, out of sync
more than 7 days after it was fetched, or stale more than 14 days after. A held
dataset is read and checked as any read checks it, so a damaged one is listed as
unusable with the reason. A dataset whose last import failed, or whose install
did not finish, says what needs attention. Datasets held that no longer apply to
this host, or that this version does not know, are listed with their size;
owatch data remove deletes one.

The report opens in the results browser on a terminal, with the same layout as an
audit.`,
		example: `  # Open the datasets in the results browser
  owatch data status

  # Print them as text instead of opening the results browser
  owatch data status --plain

  # Save them to a directory in JSON format
  owatch data status -o json --report-file /path/to/reports`,
	}, inventory{
		name:    selection.NameDatasets,
		mask:    selection.ModuleDatasets,
		label:   "datasets",
		collect: d.collectStatus,
	}, "data status")
}

// collectStatus reads the store's state and records how it ended in result,
// as each of all's modules does.
func (d *dataCmd) collectStatus(ctx context.Context, result *ScanResult) {
	view, err := d.status(ctx)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Datasets error: %v", err))
		result.Modules = append(result.Modules, erroredModule(selection.NameDatasets, err))
		return
	}
	result.Datasets = &view
	result.Modules = append(result.Modules, inventoryModule(selection.NameDatasets))
}

// status reads what the process's store holds of the known datasets.
func (d *dataCmd) status(ctx context.Context) (dataset.View, error) {
	s, err := d.open(ctx)
	if err != nil {
		return dataset.View{}, err
	}
	host, err := d.host()
	if err != nil {
		return dataset.View{}, fmt.Errorf("identify the host: %w", err)
	}
	return s.Status(d.known, host, d.now())
}

// importCmd returns owatch data import.
func (d *dataCmd) importCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import <directory>",
		Args:  cobra.ExactArgs(1),
		Short: "Install datasets from a directory, with no network",
		Long: `Install the datasets in a directory written in the store's own layout, as one
fetched on another host is. Each dataset is checked before anything is written:
one this version does not know, one that is damaged or not what its manifest
says, is refused with the reason. One that does not apply to this host is
skipped, and one older than the copy held is left, and neither is an error.

An install that fails because a file is in use is tried again; one that fails
for another reason is recorded, and owatch data status shows it until the
dataset is installed. The command exits with an error when any dataset was
refused or failed.`,
		Example: `  # Install the datasets in a directory
  owatch data import /media/usb/owatch-datasets`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return d.runImport(cmd.Context(), cmd.OutOrStdout(), args[0])
		},
	}
}

// runImport imports from into the process's store and writes one line per
// dataset.
func (d *dataCmd) runImport(ctx context.Context, out io.Writer, from string) error {
	s, err := d.open(ctx)
	if err != nil {
		return err
	}
	host, err := d.host()
	if err != nil {
		return fmt.Errorf("identify the host: %w", err)
	}
	outcomes, err := s.Import(ctx, from, d.known, host, d.now())
	if err != nil {
		return err
	}
	if len(outcomes) == 0 {
		return fmt.Errorf("no dataset found in %s", from)
	}
	refused, err := printOutcomes(out, outcomes)
	if err != nil {
		return err
	}
	if refused > 0 {
		return fmt.Errorf("%d of %s in %s not imported", refused, render.Count(len(outcomes), "dataset", "datasets"), from)
	}
	return nil
}

// printOutcomes writes one line per dataset an import or a refresh dealt
// with, and returns how many need the operator.
func printOutcomes(out io.Writer, outcomes []store.Outcome) (int, error) {
	ew := render.NewErrWriter(out)
	refused := 0
	for _, o := range outcomes {
		line := fmt.Sprintf("%s: %s", o.ID, o.Result)
		if o.Attempts > 1 || o.Result == store.Failed {
			line += " after " + render.Count(o.Attempts, "attempt", "attempts")
		}
		if o.Reason != "" {
			line += ": " + o.Reason
		}
		ew.Printf("%s\n", render.HostText(line))
		if o.NeedsAttention() {
			refused++
		}
	}
	return refused, ew.Err()
}

// removeCmd returns owatch data remove.
func (d *dataCmd) removeCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "remove <dataset>",
		Args:  cobra.ExactArgs(1),
		Short: "Delete a dataset from the store",
		Long: `Delete the dataset named from the store, with the record of any failed import
of it, and nothing else. This is the only way a dataset leaves the store: none is
removed for being old, for no longer applying to the host, or for being unknown
to this version, since a host with no network cannot fetch it again. owatch data
status lists the names.

The command asks before deleting. --yes skips the question, and is needed when
no one is at the terminal to answer.`,
		Example: `  # Delete a dataset, after a question
  owatch data remove kev

  # Delete it with no question, as a script does
  owatch data remove --yes kev`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return d.runRemove(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], yes)
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "Delete without asking first")
	return cmd
}

// runRemove deletes the dataset id from the process's store, asking first
// unless yes was given.
func (d *dataCmd) runRemove(ctx context.Context, out, prompt io.Writer, id string, yes bool) error {
	s, err := d.open(ctx)
	if err != nil {
		return err
	}
	if !yes {
		if !d.interactive() {
			return errors.New("owatch data remove asks before deleting; run it at a terminal, or pass --yes")
		}
		ok, err := render.Confirm(d.in, prompt,
			render.HostText(fmt.Sprintf("Delete the dataset %s from %s?", id, s.Root()))+" A host with no network cannot fetch it again.")
		if err != nil {
			return err
		}
		if !ok {
			_, err := fmt.Fprintln(out, "Nothing was deleted.")
			return err
		}
	}
	if err := s.Remove(ctx, id); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, render.HostText(fmt.Sprintf("Deleted %s from %s", id, s.Root())))
	return err
}
