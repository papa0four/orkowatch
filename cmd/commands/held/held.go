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
// dataset is read and kept for the rest of the run, and the time the run
// reads it at. A run's modules read one after another, so it is not made
// safe for concurrent use.
type Run struct {
	open  Opener
	known []dataset.Dataset
	now   time.Time

	opened bool
	store  store.Store
	err    error

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

// Read reads d for host from the run's store with consume, which gives the
// facts of the data it read, and says what was read or why nothing was. A
// store that cannot be opened, a dataset that is not held, and one whose data
// consume refuses are each a reason with what to run, never an error of the
// module reading it.
func (r *Run) Read(ctx context.Context, d dataset.Dataset, host *osfingerprint.OSInfo, consume func(io.Reader) (dataset.Facts, error)) dataset.Use {
	if !r.opened {
		r.store, _, r.err = r.open(ctx, r.known, host, r.now)
		r.opened = true
	}
	notDone := func(reason string) dataset.Use {
		return dataset.Use{Provenance: dataset.Provenance{ID: d.ID()}, NotDone: reason}
	}
	if r.err != nil {
		return notDone("the dataset store could not be read: " + r.err.Error())
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
