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

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/store"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/render"
)

// dataCmd is what the owatch data commands read from the host, held apart so
// a test can give each its own: the datasets owatch knows, the store, the
// host's identity, the time, and whether a person is at the terminal to ask.
type dataCmd struct {
	known       []dataset.Dataset
	open        func(context.Context) (store.Store, error)
	host        func() (*osfingerprint.OSInfo, error)
	now         func() time.Time
	interactive func() bool
	in          io.Reader
}

// knownDatasets lists the datasets this version of owatch knows. A source is
// added here as a type that satisfies dataset.Dataset; the commands and the
// store read every source through that interface and name none. None has
// landed yet: the first is CISA's Known Exploited Vulnerabilities catalog.
func knownDatasets() []dataset.Dataset {
	return nil
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
No owatch data command opens a network connection.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := cmd.Help(); err != nil {
				return fmt.Errorf("displaying help: %w", err)
			}
			return errors.New("owatch data requires a subcommand (import, remove)")
		},
	}
	cmd.AddCommand(d.importCmd(), d.removeCmd())
	return cmd
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

	ew := render.NewErrWriter(out)
	refused := 0
	for _, o := range outcomes {
		line := fmt.Sprintf("%q: %s", o.ID, o.Result)
		if o.Attempts > 1 || o.Result == store.Failed {
			line += fmt.Sprintf(" after %d attempts", o.Attempts)
		}
		if o.Reason != "" {
			line += ": " + o.Reason
		}
		ew.Printf("%s\n", line)
		if o.NeedsAttention() {
			refused++
		}
	}
	if err := ew.Err(); err != nil {
		return err
	}
	if refused > 0 {
		return fmt.Errorf("%d of the %d datasets in %s were not imported", refused, len(outcomes), from)
	}
	return nil
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
		ok, err := render.Confirm(d.in, prompt, fmt.Sprintf("Delete the dataset %q from %s? A host with no network cannot fetch it again.", id, s.Root()))
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
	_, err = fmt.Fprintf(out, "Deleted %q from %s\n", id, s.Root())
	return err
}
