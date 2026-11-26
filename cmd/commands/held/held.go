// cmd/commands/held/held.go

// Package held reads the datasets a run of owatch uses. It opens the store the
// process reads once a run, the first time a module needs it, and says of
// each dataset read what it was, or why nothing was read and what to run.
// Every module that reads a dataset reads it here, so a run installs the
// operator's datasets once and every report words a missing dataset alike.
package held

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/epss"
	"github.com/papa0four/orkowatch/internal/dataset/kev"
	"github.com/papa0four/orkowatch/internal/dataset/osv"
	"github.com/papa0four/orkowatch/internal/dataset/store"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/render"
)

// Opener opens the store a process reads, made ready to read for host at now,
// with known the datasets it may install from the operator's store.
type Opener func(ctx context.Context, known []dataset.Dataset, host *osfingerprint.OSInfo, now time.Time) (store.Store, store.Adoption, error)

// Run is the datasets one run reads: the store, opened the first time a
// dataset is read and kept for the rest of the run, what an elevated run
// installed from the operator's store on opening it, and the time the run
// reads it at. A run's modules read one after another, so it is not made
// safe for concurrent use.
type Run struct {
	open  Opener
	known []dataset.Dataset
	now   time.Time

	opened   bool
	store    store.Store
	adoption store.Adoption
	operator *dataset.Operator
	err      error

	// exploited is the catalog of known-exploited vulnerabilities, read the
	// first time it is asked for, since the software module and the audit
	// both consult it.
	exploitedRead bool
	exploited     kev.Index
	exploitedUse  dataset.Use
}

// Known lists the datasets this version of owatch knows. A source is added
// here as a type that satisfies dataset.Dataset; the commands and the store
// read every source through that interface and name none. They are listed in
// name order, which is the order status shows them in.
func Known() []dataset.Dataset {
	return append([]dataset.Dataset{epss.Scores{}, kev.Catalog{}}, osv.Datasets()...)
}

// ForHost is a run that reads this process's store, with the datasets owatch
// knows, now.
func ForHost() *Run { return New(store.ForReading, Known(), time.Now()) }

// New is a run that opens its store with open, with known the datasets it may
// install, at now.
func New(open Opener, known []dataset.Dataset, now time.Time) *Run {
	return &Run{open: open, known: known, now: now}
}

// Open is the run's store, opened for host the first time it is asked for and
// kept for the rest of the run, so an elevated run installs the operator's
// datasets once and Operator can say what it did.
func (r *Run) Open(ctx context.Context, host *osfingerprint.OSInfo) (store.Store, error) {
	if !r.opened {
		r.store, r.adoption, r.err = r.open(ctx, r.known, host, r.now)
		r.operator = operatorOf(r.adoption)
		r.opened = true
	}
	return r.store, r.err
}

// Operator is what the run, elevated, did with the operator's datasets on
// opening its store: which it installed, which it left alone and why, and
// what to run. It is nil when there is nothing to say, as for a run that is
// not elevated, found nothing newer, or never opened its store.
func (r *Run) Operator() *dataset.Operator { return r.operator }

// ElevatedHelp is what the help of a command that reads datasets says of an
// elevated run, so every such command says it alike.
const ElevatedHelp = `Run as root or from an elevated terminal, the command reads the protected
store, and first installs there what the account behind the run holds newer,
as owatch data status does. The report says what was installed and what was
left alone and why: at the head of its text, under operator in JSON and YAML,
and in the results browser's Datasets tab, whose name is drawn in red when
something needs doing.`

// Carried is the route by which datasets reach host when it has no network:
// a refresh for host on a host with one, into a directory carried here and
// imported. Every command that sends the operator there words it here, so a
// refresh that could not connect and a run that does not hold its datasets
// say it alike. A host its target cannot name, or one not identified, is
// pointed to the Target line owatch osinfo prints.
func Carried(host *osfingerprint.OSInfo) string {
	forHost := "<the Target line owatch osinfo prints here>"
	if host != nil {
		if target := host.Target(); target != "" {
			forHost = strconv.Quote(target)
		}
	}
	return "On a host with no network, run owatch data refresh --to <directory> --for " + forHost +
		" on a host with one, and owatch data import <directory> here"
}

// AskHelp is what the help of a command that reads datasets says of the
// question it asks before it starts, so every such command says it alike.
const AskHelp = `Before it collects anything, the command checks the datasets it reads, each
judged from its manifest and the size of its data without reading the data. On
a terminal, it names each that is not held or cannot be used, with what the run
would lack without it, and asks whether to go on; anything but y ends it with
what to run to get them, and --yes skips the question. With no terminal it goes
on and says in one line on standard error what it goes without.`

// noOperatorAdvice is what an elevated run with no one behind it is told,
// since it has no account's store to install from and never fetches itself.
const noOperatorAdvice = "No account is behind this elevated run, so no dataset was installed from one. " +
	"Fetch as an ordinary account with owatch data refresh --to <directory>, then run owatch data import <directory> here."

// operatorOf is what a report says of adoption, or nil when it says nothing.
func operatorOf(a store.Adoption) *dataset.Operator {
	if a.NoOperator {
		return &dataset.Operator{Advice: noOperatorAdvice}
	}
	o := dataset.Operator{Store: a.From}
	for _, outcome := range a.Outcomes {
		switch {
		case outcome.Result == store.Installed:
			o.Installed = append(o.Installed, outcome.ID)
		case outcome.NeedsAttention():
			o.Refused = append(o.Refused, dataset.Refusal{ID: outcome.ID, Reason: outcome.Reason})
		}
	}
	switch {
	case len(o.Refused) > 0:
		o.Advice = "To install what was not installed, as a deliberate act, run owatch data import " + a.From
	case len(o.Installed) == 0:
		return nil
	}
	return &o
}

// Read reads d for host from the run's store with consume, which gives the
// facts of the data it read, and says what was read or why nothing was. A
// store that cannot be opened, a dataset that is not held, and one whose data
// consume refuses are each a reason with what to run, never an error of the
// module reading it.
func (r *Run) Read(ctx context.Context, d dataset.Dataset, host *osfingerprint.OSInfo, consume func(io.Reader) (dataset.Facts, error)) dataset.Use {
	notDone := func(reason string) dataset.Use {
		return dataset.Use{Provenance: dataset.Provenance{ID: d.ID()}, NotDone: reason}
	}
	if _, err := r.Open(ctx, host); err != nil {
		return notDone("the dataset store could not be read: " + err.Error())
	}

	var facts dataset.Facts
	manifest, err := r.store.Read(d, r.now, func(data io.Reader) error {
		var readErr error
		facts, readErr = consume(data)
		return readErr
	})
	switch {
	case errors.Is(err, store.ErrNotHeld):
		return notDone(fmt.Sprintf("%s is not held; fetch it with owatch data refresh, or install it with owatch data import", d.ID()))
	case err != nil:
		return notDone(fmt.Sprintf("%s cannot be used: %s; fetch it again with owatch data refresh", d.ID(), strings.TrimSpace(err.Error())))
	}
	return dataset.Use{Provenance: dataset.ProvenanceOf(d.ID(), manifest, facts, r.now)}
}

// Exploited is CISA's catalog of known-exploited vulnerabilities as the run
// read it for host, read once however often it is asked for: its index, empty
// when it was not read, and what was read or why nothing was.
func (r *Run) Exploited(ctx context.Context, host *osfingerprint.OSInfo) (kev.Index, dataset.Use) {
	if !r.exploitedRead {
		catalog := kev.Catalog{}
		r.exploitedUse = r.Read(ctx, catalog, host, func(data io.Reader) (facts dataset.Facts, err error) {
			r.exploited, facts, err = catalog.Read(data, host)
			return facts, err
		})
		if r.exploitedUse.NotDone != "" {
			r.exploited = kev.Index{}
		}
		r.exploitedRead = true
	}
	return r.exploited, r.exploitedUse
}

// Catalog is the catalog of known-exploited vulnerabilities, which Exploited
// reads, as a run that consults it names it among the datasets it reads.
func Catalog() dataset.Dataset { return kev.Catalog{} }

// ErrDeclined is a run the operator chose not to start without the datasets
// it does not hold. The error that carries it says what to run to get them.
var ErrDeclined = errors.New("run canceled: datasets it reads are not held")

// Gap is a dataset a run reads that its store cannot give it: the dataset,
// what the run lacks without it, and why it cannot be read.
type Gap struct {
	ID, Gives, Reason string
}

// String is the gap as the question before a run names it.
func (g Gap) String() string {
	return fmt.Sprintf("%s (%s): %s", g.ID, g.Gives, g.Reason)
}

// missing is what of needed, the datasets a run reads, the run's store cannot
// give it for host, each named once in the order needed first gives it. It
// opens the store as a read does, so an elevated run has installed what the
// operator holds newer before it is judged, and judges each dataset that
// applies to host as a read would before reading its data, without reading
// any. A dataset that does not apply to host is not read, and is no gap.
func (r *Run) missing(ctx context.Context, host *osfingerprint.OSInfo, needed []dataset.Dataset) []Gap {
	var gaps []Gap
	seen := make(map[string]bool, len(needed))
	for _, d := range needed {
		if seen[d.ID()] || !d.AppliesTo(host) {
			continue
		}
		seen[d.ID()] = true
		if reason := r.unreadable(ctx, d, host); reason != "" {
			gaps = append(gaps, Gap{ID: d.ID(), Gives: d.Gives(), Reason: reason})
		}
	}
	return gaps
}

// unreadable is why d cannot be read for host from the run's store, or
// nothing when it can.
func (r *Run) unreadable(ctx context.Context, d dataset.Dataset, host *osfingerprint.OSInfo) string {
	if _, err := r.Open(ctx, host); err != nil {
		return "the dataset store could not be read: " + err.Error()
	}
	switch err := r.store.Usable(d, r.now); {
	case errors.Is(err, store.ErrNotHeld):
		return "not held"
	case err != nil:
		return "cannot be used: " + strings.TrimSpace(err.Error())
	}
	return ""
}

// Reads is what a run reads for host: the datasets each part of it would
// read, which for some depend on the host's distribution.
type Reads func(host *osfingerprint.OSInfo) []dataset.Dataset

// Ask settles, before anything of a run is collected, whether the run goes on
// without the datasets it reads that it cannot read here, so it learns at its
// start, not in its report, what it would go without. With yes, or for a run
// that reads no dataset, reads nil, it goes on, and nothing is judged and the
// host is not identified. Otherwise the host is identified as its fingerprint
// reads it, or taken as unknown when it cannot be, so only the datasets that
// apply to every host are judged and the module that reads the fingerprint
// reports why; the datasets are judged as missing does, and the run settles
// as settle does.
func (r *Run) Ask(ctx context.Context, reads Reads, yes, interactive bool, in io.Reader, out io.Writer) error {
	if yes || reads == nil {
		return nil
	}
	host, err := osfingerprint.GetOSFingerprint()
	if err != nil {
		host = nil
	}
	return r.settle(r.missing(ctx, host, reads(host)), host, interactive, in, out)
}

// settle is whether a run goes on without gaps. With none it goes on. With no
// one at the terminal to answer, it goes on and says on out, in one line, what
// it goes without, since the report then says what was not read and a script
// is not stopped. Otherwise it names each gap and asks; anything but yes is
// ErrDeclined with what to run for host.
func (r *Run) settle(gaps []Gap, host *osfingerprint.OSInfo, interactive bool, in io.Reader, out io.Writer) error {
	if len(gaps) == 0 {
		return nil
	}
	named := make([]string, len(gaps))
	for i, g := range gaps {
		named[i] = render.HostText(g.String())
	}
	if !interactive {
		_, err := fmt.Fprintln(out, "This run goes without "+strings.Join(named, "; ")+"; its report says what was not read.")
		return err
	}
	if _, err := fmt.Fprintln(out, "This run reads datasets it cannot read here, and would go without what they give:\n  "+strings.Join(named, "\n  ")); err != nil {
		return err
	}
	switch ok, err := render.Confirm(in, out, "Continue without them?"); {
	case err != nil:
		return err
	case !ok:
		return fmt.Errorf("%w. %s", ErrDeclined, r.toFetch(host))
	}
	return nil
}

// toFetch is what to run for host to hold what a run reads: a refresh by the
// account behind the run, and the route for a host with no network. An
// elevated run is told to refresh as the account behind it and install what
// that fetched, since an elevated run never fetches, and one with no account
// behind it is told how datasets reach the host.
func (r *Run) toFetch(host *osfingerprint.OSInfo) string {
	switch {
	case r.adoption.NoOperator:
		return noOperatorAdvice
	case r.adoption.From != "":
		return "As the account whose store is " + r.adoption.From + ", not elevated, run owatch data refresh, " +
			"then run owatch data status elevated to install what it fetched. " + Carried(host) + "."
	}
	return "Run owatch data refresh. " + Carried(host) + "."
}
