// cmd/commands/vulnerabilities.go

package cmd

import (
	"context"
	"fmt"
	"io"

	"github.com/papa0four/orkowatch/cmd/commands/held"
	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/epss"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/softwarelist"
	"github.com/papa0four/orkowatch/internal/vulnmatch"
	"github.com/papa0four/orkowatch/internal/vulnrecord"
)

// recordSource is a dataset of a distribution's security records that the
// installed packages are matched against: the manager whose packages it
// names, how its records of one vulnerability combine, its records given one
// at a time as they are checked, and the release whose records a match of a
// host reads, which a match carries as its Version.
type recordSource interface {
	dataset.Dataset
	Manager() string
	Combining() vulnrecord.Combining
	Records(data io.Reader, host *osfingerprint.OSInfo, each func(vulnrecord.Record) error) (dataset.Facts, error)
	Release(host *osfingerprint.OSInfo) (string, error)
}

// inventoryMatching is what matching the software inventory reads from the
// host, held apart so a test can give each its own: the host's identity when
// the run did not read it, and the datasets the inventory is matched against,
// with the distributions they cover.
type inventoryMatching struct {
	host     func() (*osfingerprint.OSInfo, error)
	matched  []dataset.Dataset
	coverage string
}

// coverage names the systems whose packages matching covers, as a match not
// made and the help of owatch software name them: OSV's distributions,
// Fedora, whose updates repository covers its packages, and FreeBSD, whose
// packages VuXML covers.
const coverage = "AlmaLinux, Alpine, Fedora, FreeBSD, Red Hat Enterprise Linux, Rocky Linux, and Ubuntu"

// hostMatching is inventoryMatching that reads this host.
func hostMatching() inventoryMatching {
	return inventoryMatching{
		host:     osfingerprint.GetOSFingerprint,
		matched:  held.Matched(),
		coverage: coverage,
	}
}

// run matches entries, the inventory of host, against the datasets of host's
// system as data reads them, marks the vulnerabilities known to be
// exploited, scores them from EPSS, and says what it found. host is read when
// the run did not read it. A match that cannot be made says why and what to
// do, and is never an error of the inventory: the packages are still listed.
// The first dataset is the one the match is of, and with it not read no
// match is made; another, such as a release's tracking bugs beside its
// updates, adds its records when it is read, and the view says what it read
// or why it read nothing.
func (m inventoryMatching) run(ctx context.Context, data *held.Run, host *osfingerprint.OSInfo, entries []softwarelist.SoftwareEntry) *vulnmatch.View {
	if host == nil {
		var err error
		if host, err = m.host(); err != nil {
			return notDone("", "the host could not be identified: "+err.Error())
		}
	}
	sources, failed := m.recordSources(host)
	if failed != nil {
		return failed
	}
	first := sources[0]
	matcher, err := vulnmatch.New(first.Manager(), first.Combining(), entries)
	if err != nil {
		return notDone(first.ID(), err.Error())
	}
	use := data.Read(ctx, first, host, func(r io.Reader) (dataset.Facts, error) {
		return first.Records(r, host, matcher.Add)
	})
	if use.NotDone != "" {
		return notDone(first.ID(), use.NotDone)
	}
	var also []dataset.Use
	for _, source := range sources[1:] {
		also = append(also, readAlso(ctx, data, source, host, matcher))
	}
	v := matcher.Result()
	v.Use, v.Also = use, also
	v.MarkExploited(data.Exploited(ctx, host))
	v.MarkPredicted(predicted(ctx, data, host, v))
	return &v
}

// recordSources are the datasets host's inventory is matched against, or the
// view of a match that cannot be made and why: none applies to host, one
// holds no records, or they name packages of different managers or combine
// their records differently, which one matcher cannot judge together.
func (m inventoryMatching) recordSources(host *osfingerprint.OSInfo) ([]recordSource, *vulnmatch.View) {
	chosen := m.sources(host)
	if len(chosen) == 0 {
		return nil, notDone("", fmt.Sprintf("no dataset owatch knows covers this host's packages; matching covers %s", m.coverage))
	}
	var sources []recordSource
	for _, d := range chosen {
		source, ok := d.(recordSource)
		if !ok {
			return nil, notDone(d.ID(), "the dataset holds no records to match against")
		}
		if len(sources) > 0 && (source.Manager() != sources[0].Manager() || source.Combining() != sources[0].Combining()) {
			return nil, notDone(sources[0].ID(), fmt.Sprintf("%s and %s cannot be matched together: they name packages of different managers or combine their records differently", sources[0].ID(), source.ID()))
		}
		sources = append(sources, source)
	}
	return sources, nil
}

// readAlso reads source, a dataset matched against beside the first, and
// gives its records to matcher only once it was read whole, so a dataset
// that fails partway adds nothing; it returns what was read or why nothing
// was.
func readAlso(ctx context.Context, data *held.Run, source recordSource, host *osfingerprint.OSInfo, matcher *vulnmatch.Matcher) dataset.Use {
	var records []vulnrecord.Record
	use := data.Read(ctx, source, host, func(r io.Reader) (dataset.Facts, error) {
		records = records[:0]
		return source.Records(r, host, func(rec vulnrecord.Record) error {
			records = append(records, rec)
			return nil
		})
	})
	if use.NotDone != "" {
		return use
	}
	for _, rec := range records {
		if err := matcher.Add(rec); err != nil {
			return dataset.Use{Provenance: dataset.Provenance{ID: source.ID()}, NotDone: err.Error()}
		}
	}
	return use
}

// sources are the datasets owatch knows that host's inventory is matched
// against, in the order owatch lists them; the first is the one a match is
// of.
func (m inventoryMatching) sources(host *osfingerprint.OSInfo) []dataset.Dataset {
	var out []dataset.Dataset
	for _, d := range m.matched {
		if d.AppliesTo(host) {
			out = append(out, d)
		}
	}
	return out
}

// source is the dataset a match of host's inventory is of, or nil when none
// owatch knows applies to host.
func (m inventoryMatching) source(host *osfingerprint.OSInfo) dataset.Dataset {
	if s := m.sources(host); len(s) > 0 {
		return s[0]
	}
	return nil
}

// release is the dataset and the release a match of host reads, the ID and
// Version that match carries, or why no match of host is made.
func (m inventoryMatching) release(host *osfingerprint.OSInfo) (id, release string, err error) {
	chosen := m.source(host)
	if chosen == nil {
		return "", "", fmt.Errorf("no dataset owatch knows covers this host's packages; matching covers %s", m.coverage)
	}
	source, ok := chosen.(recordSource)
	if !ok {
		return chosen.ID(), "", fmt.Errorf("%s holds no records to match against", chosen.ID())
	}
	release, err = source.Release(host)
	return source.ID(), release, err
}

// reads is what matching reads for host: the datasets of its system, and
// then the catalog and the scores, which mark and score what was matched. It
// reads none of them for a host no dataset covers, since no match is made.
func (m inventoryMatching) reads(host *osfingerprint.OSInfo) []dataset.Dataset {
	sources := m.sources(host)
	if len(sources) == 0 {
		return nil
	}
	return append(sources, held.Catalog(), epss.Scores{})
}

// predicted reads the EPSS scores file through data, keeping the predictions
// of the vulnerabilities v matched and no others: its index, empty when it was
// not read, and what was read or why nothing was.
func predicted(ctx context.Context, data *held.Run, host *osfingerprint.OSInfo, v vulnmatch.View) (epss.Index, dataset.Use) {
	matched := make(map[string]bool)
	for _, pkg := range v.Packages {
		for _, found := range pkg.Vulnerabilities {
			matched[found.ID] = true
		}
	}
	scores := epss.Scores{}
	var x epss.Index
	use := data.Read(ctx, scores, host, func(r io.Reader) (facts dataset.Facts, err error) {
		x, facts, err = scores.Read(r, func(cve string) bool { return matched[cve] })
		return facts, err
	})
	if use.NotDone != "" {
		x = epss.Index{}
	}
	return x, use
}

// notDone is the view of a match that was not made, for the dataset named id
// when one was chosen.
func notDone(id, reason string) *vulnmatch.View {
	v := vulnmatch.View{Use: dataset.Use{Provenance: dataset.Provenance{ID: id}, NotDone: reason}, Packages: []vulnmatch.PackageMatches{}}
	return &v
}
