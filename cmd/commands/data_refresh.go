// cmd/commands/data_refresh.go

// owatch data refresh, and the steps it runs, which r in the results browser
// runs too: the one way owatch opens a network connection. This is the only
// file that may import the package that connects.

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/cmd/commands/cliargs"
	"github.com/papa0four/orkowatch/cmd/commands/held"
	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/fetch"
	"github.com/papa0four/orkowatch/internal/dataset/progress"
	"github.com/papa0four/orkowatch/internal/dataset/store"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/render"
)

// largeDownload is the size past which a dataset is asked about before it is
// fetched, so a first refresh over a metered or slow link is a choice.
const largeDownload = 100 << 20

// fetcher is what brings a dataset from its origin: where its data is for a
// host and how large it is there, how long a download of that size is
// allowed, and the data from where it was found.
type fetcher interface {
	Locate(ctx context.Context, d dataset.Dataset, host *osfingerprint.OSInfo) (fetch.Source, error)
	TimeLimit(size int64) time.Duration
	Fetch(ctx context.Context, d dataset.Dataset, src fetch.Source, w io.Writer) error
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
from the address its source publishes it at. It, and r in the results browser
of owatch software and owatch all, which runs its steps, are the only ways
owatch opens a network connection. It connects over HTTPS to the hosts the
datasets themselves name and to no other, sends nothing about this host, reads
no more than a dataset's origin may serve, and gives up on a download that runs
past the time its size allows or that receives nothing for a minute. A proxy
named by HTTPS_PROXY is used; no other environment variable changes where it
connects.

Each dataset's size, and the time its download is allowed, is printed before it
is fetched: its size at 256 KiB a second, and never less than ten minutes. One
larger than 100 MiB is asked about first; --yes skips the question, and is
needed for such a dataset when no one is at the terminal. What is fetched is
checked as any dataset is before it replaces the copy held. A download that
fails because a server is briefly unable to answer, or that stalls, is tried
three times; one that fails for another reason once. A dataset that could not
be refreshed keeps the copy held, and owatch data status shows the failure
until it is refreshed. A refresh that can make no connection at all, as on a
host with no network, stops there, fetches nothing after it, and names the way
to bring datasets to such a host: --to and --for on a host with a network, then
owatch data import here.

While it runs, each download shows what has been received of its size, for how
long, and how fast, and how long nothing has come once that is five seconds;
keeping the records this host needs, the check, and the install are each named
as they run. On a terminal the line is rewritten in place; anywhere else each
step gets a line as it begins and as it ends.

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
	host, err := d.refreshHost(to, forHost)
	if err != nil {
		return err
	}
	plan, err := d.planRefresh(ctx, host)
	if err != nil {
		return err
	}
	if len(plan.datasets) == 0 {
		whose := "this host"
		if forHost != "" {
			whose = "the host " + forHost
		}
		_, err := fmt.Fprintln(out, render.HostText("This version of owatch knows no dataset for "+whose+"; nothing was fetched."))
		return err
	}
	dest, err := d.refreshDest(ctx, to)
	if err != nil {
		return err
	}

	report := progress.New(out, d.width, d.now)
	chosen, declined, err := d.choose(out, prompt, plan.datasets, yes, report)
	if err != nil {
		return err
	}
	report.Start()
	outcomes, err := plan.fetch(ctx, dest, chosen, d.now(), report)
	err = errors.Join(err, report.Stop())
	unreached := errors.Is(err, store.ErrUnreachable)
	if err != nil && !unreached {
		return err
	}
	failed, perr := printOutcomes(out, outcomes)
	if perr != nil {
		return perr
	}
	if unreached {
		return noNetwork(err, host)
	}
	if failed+declined > 0 {
		return fmt.Errorf("%d of %s not refreshed", failed+declined, render.Count(len(plan.datasets), "dataset", "datasets"))
	}
	return nil
}

// planned is a dataset a refresh would fetch and what its download is to be:
// where its data was found, or why it was not; the address the download is
// named by; its size, as its origin states it or, when the origin states
// none, the most a fetch may read; and the time the download is allowed.
type planned struct {
	dataset dataset.Dataset
	source  fetch.Source
	missed  error
	address string
	size    int64
	stated  bool
	allowed time.Duration
}

// large reports whether the download is asked about before it is fetched.
func (p planned) large() bool { return p.size > largeDownload }

// described is the download's size as a refresh names it: as stated, or as
// what it may be at most.
func (p planned) described() string {
	if !p.stated {
		return "up to " + dataset.Size(p.size)
	}
	return dataset.Size(p.size)
}

// String is the line a refresh states the download in before it begins.
func (p planned) String() string {
	return fmt.Sprintf("%s: %s from %s, allowed %s", p.dataset.ID(), p.described(), p.address, p.allowed)
}

// brief is the line without the address the data is fetched from, for the
// results browser, where a long address would not fit beside the size. The
// address is in owatch data refresh and owatch data status.
func (p planned) brief() string {
	return fmt.Sprintf("%s: %s, allowed %s", p.dataset.ID(), p.described(), p.allowed)
}

// refreshPlan is what a refresh for host would fetch: each dataset that
// applies to host with its download, and the fetcher that sized them, which
// alone fetches them.
type refreshPlan struct {
	host     *osfingerprint.OSInfo
	datasets []planned
	f        fetcher
}

// planRefresh is the refresh of the datasets that apply to host, each located
// and sized by its origin. It writes and asks nothing, opens no connection but
// those that locate and size the data, and refuses an elevated process before
// building a fetcher, so no caller can plan a refresh that runs elevated. A
// dataset that could not be located is still planned, by its origin's first
// address, and is located again when it is fetched.
func (d *dataCmd) planRefresh(ctx context.Context, host *osfingerprint.OSInfo) (refreshPlan, error) {
	if d.elevated() {
		return refreshPlan{}, errRefreshElevated
	}
	plan := refreshPlan{host: host}
	var wanted []dataset.Dataset
	for _, known := range d.known {
		if known.AppliesTo(host) {
			wanted = append(wanted, known)
		}
	}
	if len(wanted) == 0 {
		return plan, nil
	}
	f, err := d.fetcher()
	if err != nil {
		return refreshPlan{}, err
	}
	plan.f = f
	for _, w := range wanted {
		src, err := f.Locate(ctx, w, host)
		p := planned{dataset: w, source: src, missed: err, address: src.URL, size: src.Size, stated: src.Stated && err == nil}
		if err != nil {
			p.address = w.Origin(host).URL
		}
		if !p.stated {
			// The server did not say, so the most its file may hold is
			// what a fetch could read.
			p.size = dataset.FetchLimit(w)
		}
		p.allowed = f.TimeLimit(p.size)
		plan.datasets = append(plan.datasets, p)
	}
	return plan, nil
}

// fetch fetches chosen, datasets of the plan, into dest, telling progress each
// step, and returns what came of each. Each is fetched from where the plan
// found it, through every attempt, so what is fetched is what was named; one
// the plan could not locate is located again first. A refresh that can make
// no connection ends with store.ErrUnreachable.
func (p refreshPlan) fetch(ctx context.Context, dest store.Store, chosen []planned, now time.Time, progress store.Progress) ([]store.Outcome, error) {
	datasets := make([]dataset.Dataset, len(chosen))
	found := make(map[string]*planned, len(chosen))
	for i := range chosen {
		datasets[i] = chosen[i].dataset
		found[chosen[i].dataset.ID()] = &chosen[i]
	}
	from := func(ctx context.Context, d dataset.Dataset, w io.Writer) error {
		c := found[d.ID()]
		if c.missed != nil {
			src, err := p.f.Locate(ctx, d, p.host)
			if err != nil {
				return err
			}
			c.source, c.missed = src, nil
		}
		return p.f.Fetch(ctx, d, c.source, w)
	}
	return dest.Reporting(progress).Refresh(ctx, from, datasets, p.host, now)
}

// noNetwork is the end of a refresh that could make no connection, with the
// route for a host with no network.
func noNetwork(cause error, host *osfingerprint.OSInfo) error {
	return fmt.Errorf("%w; nothing after it was fetched. %s", cause, held.Carried(host))
}

// refreshHost settles which host is fetched for: the host --for names, which
// needs --to, since its datasets have no use in this host's store, or this
// host.
func (d *dataCmd) refreshHost(to, forHost string) (*osfingerprint.OSInfo, error) {
	switch {
	case forHost != "" && to == "":
		return nil, errors.New("--for names another host, whose datasets have no use in this host's store; name a directory to carry them in with --to")
	case forHost == "":
		return d.host()
	}
	host, err := osfingerprint.ParseTarget(forHost)
	if err != nil {
		return nil, fmt.Errorf("--for: %w", err)
	}
	return host, nil
}

// refreshDest is where a refresh puts the datasets: the directory to, or the
// account's store.
func (d *dataCmd) refreshDest(ctx context.Context, to string) (store.Store, error) {
	if to != "" {
		return store.At(to), nil
	}
	return d.open(ctx)
}

// choose prints the download of each of wanted, tells report how large each
// is to be, and returns those to fetch: every one that is not large, and each
// large one the operator agrees to, or all with yes. It returns how many large
// ones were declined, or could not be asked about.
func (d *dataCmd) choose(out, prompt io.Writer, wanted []planned, yes bool, report *progress.Report) (chosen []planned, declined int, err error) {
	ew := render.NewErrWriter(out)
	for _, w := range wanted {
		report.Expect(w.dataset.ID(), w.size, w.stated)
		ew.Printf("%s\n", render.HostText(w.String()))

		switch {
		case !w.large() || yes:
			chosen = append(chosen, w)
		case !d.interactive():
			ew.Printf("%s\n", render.HostText(fmt.Sprintf("%s: not fetched: it is larger than %s; pass --yes to fetch it", w.dataset.ID(), dataset.Size(largeDownload))))
			declined++
		default:
			ok, err := render.Confirm(d.in, prompt, render.HostText(fmt.Sprintf("Fetch %s, %s?", w.dataset.ID(), w.described())))
			if err != nil {
				return nil, 0, err
			}
			if ok {
				chosen = append(chosen, w)
			} else {
				ew.Printf("%s\n", render.HostText(w.dataset.ID()+": not fetched"))
				declined++
			}
		}
	}
	return chosen, declined, ew.Err()
}
