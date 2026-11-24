// cmd/commands/vulnerabilities.go

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/osv"
	"github.com/papa0four/orkowatch/internal/dataset/store"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/softwarelist"
	"github.com/papa0four/orkowatch/internal/vulnmatch"
)

// recordSource is a dataset of a distribution's security records that the
// installed packages are matched against: the manager whose packages it
// names, and its records given one at a time as they are checked.
type recordSource interface {
	dataset.Dataset
	Manager() string
	Records(data io.Reader, host *osfingerprint.OSInfo, each func(osv.Record) error) (dataset.Facts, error)
}

// inventoryMatching is what matching the software inventory reads from the
// host, held apart so a test can give each its own: the host's identity when
// the run did not read it, the store made ready to read, the time, the
// datasets the inventory is matched against, and every dataset owatch knows,
// which an elevated run installs from the operator's store before reading.
type inventoryMatching struct {
	host     func() (*osfingerprint.OSInfo, error)
	read     func(context.Context, []dataset.Dataset, *osfingerprint.OSInfo, time.Time) (store.Store, store.Adoption, error)
	now      func() time.Time
	matched  []dataset.Dataset
	known    []dataset.Dataset
	coverage string
}

// hostMatching is inventoryMatching that reads this host.
func hostMatching() inventoryMatching {
	return inventoryMatching{
		host:     osfingerprint.GetOSFingerprint,
		read:     store.ForReading,
		now:      time.Now,
		matched:  osv.Datasets(),
		known:    knownDatasets(),
		coverage: "AlmaLinux, Alpine, Red Hat Enterprise Linux, Rocky Linux, and Ubuntu",
	}
}

// run matches entries, the inventory of host, against the dataset of host's
// distribution, and says what it found. host is read when the run did not
// read it. A match that cannot be made says why and what to do, and is never
// an error of the inventory: the packages are still listed.
func (m inventoryMatching) run(ctx context.Context, host *osfingerprint.OSInfo, entries []softwarelist.SoftwareEntry) *vulnmatch.View {
	if host == nil {
		var err error
		if host, err = m.host(); err != nil {
			return notDone("", "the host could not be identified: "+err.Error())
		}
	}
	at := slices.IndexFunc(m.matched, func(d dataset.Dataset) bool { return d.AppliesTo(host) })
	if at < 0 {
		return notDone("", fmt.Sprintf("no dataset owatch knows covers this host's packages; matching covers %s", m.coverage))
	}
	source, ok := m.matched[at].(recordSource)
	if !ok {
		return notDone(m.matched[at].ID(), "the dataset holds no records to match against")
	}

	now := m.now()
	s, _, err := m.read(ctx, m.known, host, now)
	if err != nil {
		return notDone(source.ID(), "the dataset store could not be read: "+err.Error())
	}
	matcher, err := vulnmatch.New(source.Manager(), entries)
	if err != nil {
		return notDone(source.ID(), err.Error())
	}
	var facts dataset.Facts
	manifest, err := s.Read(source, now, func(data io.Reader) error {
		var readErr error
		facts, readErr = source.Records(data, host, matcher.Add)
		return readErr
	})
	switch {
	case errors.Is(err, store.ErrNotHeld):
		return notDone(source.ID(), fmt.Sprintf("%s is not held; fetch it with owatch data refresh, or install it with owatch data import", source.ID()))
	case err != nil:
		return notDone(source.ID(), fmt.Sprintf("%s cannot be used: %s; fetch it again with owatch data refresh", source.ID(), strings.TrimSpace(err.Error())))
	}

	v := matcher.Result()
	v.Dataset, v.Release, v.Source = source.ID(), facts.Version, manifest.Source
	v.DataDate = facts.Date.UTC().Format(time.DateOnly)
	v.Fetched = manifest.Fetched.UTC().Format(time.RFC3339)
	v.State = string(dataset.StateAt(manifest.Fetched, now))
	return &v
}

// notDone is the view of a match that was not made, for the dataset named id
// when one was chosen.
func notDone(id, reason string) *vulnmatch.View {
	v := vulnmatch.View{Dataset: id, NotDone: reason, Packages: []vulnmatch.PackageMatches{}}
	return &v
}
