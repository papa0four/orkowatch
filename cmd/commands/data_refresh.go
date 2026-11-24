// cmd/commands/data_refresh.go

// owatch data refresh, the one command that opens a network connection. This
// is the only file that may import the package that connects.

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/cmd/commands/cliargs"
	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/fetch"
	"github.com/papa0four/orkowatch/internal/dataset/store"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/render"
)

// largeDownload is the size past which a dataset is asked about before it is
// fetched, so a first refresh over a metered or slow link is a choice.
const largeDownload = 100 << 20

// fetcher is what brings a dataset from its origin: how large it is there,
// and its data.
type fetcher interface {
	Size(ctx context.Context, d dataset.Dataset) (size int64, stated bool, err error)
	Fetch(ctx context.Context, d dataset.Dataset, w io.Writer) error
}

// newFetcher returns the fetcher that connects to the datasets' origins.
func newFetcher() (fetcher, error) {
	return fetch.New()
}

// errRefreshElevated is the refusal of an elevated refresh, with what to do
// instead.
var errRefreshElevated = errors.New("owatch data refresh does not run as root or from an elevated terminal: " +
	"run it as an ordinary account, and an elevated owatch data status then installs what it fetched; " +
	"or run it on another host with --to and bring the directory here for owatch data import")

// refreshCmd returns owatch data refresh.
func (d *dataCmd) refreshCmd() *cobra.Command {
	var (
		to      string
		forHost string
		yes     bool
	)
	cmd := &cobra.Command{
		Use:   "refresh",
		Args:  cliargs.None,
		Short: "Fetch the datasets this host needs, over HTTPS",
		Long: `Fetch the datasets that apply to this host into the account's store, each
from the address its source publishes it at. This is the only owatch command
that opens a network connection. It connects over HTTPS to the hosts the
datasets themselves name and to no other, sends nothing about this host, reads
no more than a dataset may hold, and gives up on a download after a fixed time.
A proxy named by HTTPS_PROXY is used; no other environment variable changes
where it connects.

Each dataset's size is printed before it is fetched. One larger than 100 MiB is
asked about first; --yes skips the question, and is needed for such a dataset
when no one is at the terminal. What is fetched is checked as any dataset is
before it replaces the copy held. A download that fails because a server is
briefly unable to answer is tried three times; one that fails for another
reason once. A dataset that could not be refreshed keeps the copy held, and
owatch data status shows the failure until it is refreshed.

--to writes the datasets to a directory to carry to another host, where owatch
data import installs them. --for names that host by the Target line owatch
osinfo prints there, os/platform/version, copied as it is printed. Quote it
when it holds a space, as Windows does.

refresh never runs as root or from an elevated terminal, and no flag changes
that. An elevated owatch data status installs what an ordinary account
refreshed.`,
		Example: `  # Fetch the datasets this host needs
  owatch data refresh

  # Fetch them into a directory to carry to a host with no network
  owatch data refresh --to /media/usb/owatch-datasets

  # Fetch the datasets another host needs
  owatch data refresh --to /media/usb/owatch-datasets --for linux/ubuntu/22.04

  # Fetch through a proxy, and without questions
  HTTPS_PROXY=http://proxy.example:3128 owatch data refresh --yes`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return d.runRefresh(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), to, forHost, yes)
		},
	}
	cmd.Flags().StringVar(&to, "to", "", "Write the datasets to this directory instead of the store, to carry to another host")
	cmd.Flags().StringVar(&forHost, "for", "", "Fetch for another host, named by the Target line owatch osinfo prints there (requires --to)")
	cmd.Flags().BoolVar(&yes, "yes", false, "Fetch a dataset larger than 100 MiB without asking first")
	return cmd
}

// runRefresh fetches the datasets that apply to the host into the store, or
// into the directory to.
func (d *dataCmd) runRefresh(ctx context.Context, out, prompt io.Writer, to, forHost string, yes bool) error {
	if d.elevated() {
		return errRefreshElevated
	}
	host, dest, err := d.refreshTarget(ctx, to, forHost)
	if err != nil {
		return err
	}

	var wanted []dataset.Dataset
	for _, known := range d.known {
		if known.AppliesTo(host) {
			wanted = append(wanted, known)
		}
	}
	if len(wanted) == 0 {
		whose := "this host"
		if forHost != "" {
			whose = "the host " + forHost
		}
		_, err := fmt.Fprintln(out, render.HostText("This version of owatch knows no dataset for "+whose+"; nothing was fetched."))
		return err
	}

	f, err := d.fetcher()
	if err != nil {
		return err
	}
	chosen, declined, err := d.choose(ctx, out, prompt, f, wanted, yes)
	if err != nil {
		return err
	}
	outcomes, err := dest.Refresh(ctx, f.Fetch, chosen, host, d.now())
	if err != nil {
		return err
	}
	failed, err := printOutcomes(out, outcomes)
	if err != nil {
		return err
	}
	if failed+declined > 0 {
		return fmt.Errorf("%d of %s not refreshed", failed+declined, render.Count(len(wanted), "dataset", "datasets"))
	}
	return nil
}

// refreshTarget settles which host is fetched for and where the datasets go:
// this host and the account's store, or with --to a directory, for the host
// --for names when it is given.
func (d *dataCmd) refreshTarget(ctx context.Context, to, forHost string) (*osfingerprint.OSInfo, store.Store, error) {
	if forHost != "" && to == "" {
		return nil, store.Store{}, errors.New("--for names another host, whose datasets have no use in this host's store; name a directory to carry them in with --to")
	}
	var host *osfingerprint.OSInfo
	var err error
	if forHost != "" {
		host, err = osfingerprint.ParseTarget(forHost)
		if err != nil {
			err = fmt.Errorf("--for: %w", err)
		}
	} else {
		host, err = d.host()
	}
	if err != nil {
		return nil, store.Store{}, err
	}
	if to != "" {
		return host, store.At(to), nil
	}
	dest, err := d.open(ctx)
	return host, dest, err
}

// choose prints the size of each of wanted and returns those to fetch: every
// one that is not large, and each large one the operator agrees to, or all
// with yes. It returns how many large ones were declined, or could not be
// asked about.
func (d *dataCmd) choose(ctx context.Context, out, prompt io.Writer, f fetcher, wanted []dataset.Dataset, yes bool) (chosen []dataset.Dataset, declined int, err error) {
	ew := render.NewErrWriter(out)
	for _, w := range wanted {
		size, stated, sizeErr := f.Size(ctx, w)
		described := dataset.Size(size)
		if sizeErr != nil || !stated {
			// The server did not say, so the most its file may hold is
			// what a fetch could read.
			size, described = dataset.FetchLimit(w), "up to "+dataset.Size(dataset.FetchLimit(w))
		}
		ew.Printf("%s\n", render.HostText(fmt.Sprintf("%s: %s from %s", w.ID(), described, w.Origin().URL)))

		switch {
		case size <= largeDownload || yes:
			chosen = append(chosen, w)
		case !d.interactive():
			ew.Printf("%s\n", render.HostText(fmt.Sprintf("%s: not fetched: it is larger than %s; pass --yes to fetch it", w.ID(), dataset.Size(largeDownload))))
			declined++
		default:
			ok, err := render.Confirm(d.in, prompt, render.HostText(fmt.Sprintf("Fetch %s, %s?", w.ID(), described)))
			if err != nil {
				return nil, 0, err
			}
			if ok {
				chosen = append(chosen, w)
			} else {
				ew.Printf("%s\n", render.HostText(w.ID()+": not fetched"))
				declined++
			}
		}
	}
	return chosen, declined, ew.Err()
}
