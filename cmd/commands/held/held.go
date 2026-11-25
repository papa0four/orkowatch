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
	"strings"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/epss"
	"github.com/papa0four/orkowatch/internal/dataset/kev"
	"github.com/papa0four/orkowatch/internal/dataset/osv"
	"github.com/papa0four/orkowatch/internal/dataset/store"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
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
		var adoption store.Adoption
		r.store, adoption, r.err = r.open(ctx, r.known, host, r.now)
		r.operator = operatorOf(adoption)
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
