// cmd/commands/vulnerabilities.go

package cmd

import (
	"context"
	"fmt"
	"io"
	"slices"

	"github.com/papa0four/orkowatch/cmd/commands/held"
	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/epss"
	"github.com/papa0four/orkowatch/internal/dataset/osv"
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
// the run did not read it, and the datasets the inventory is matched against,
// with the distributions they cover.
type inventoryMatching struct {
	host     func() (*osfingerprint.OSInfo, error)
	matched  []dataset.Dataset
	coverage string
}

// hostMatching is inventoryMatching that reads this host.
func hostMatching() inventoryMatching {
	return inventoryMatching{
		host:     osfingerprint.GetOSFingerprint,
		matched:  osv.Datasets(),
		coverage: "AlmaLinux, Alpine, Red Hat Enterprise Linux, Rocky Linux, and Ubuntu",
	}
}

// run matches entries, the inventory of host, against the dataset of host's
// distribution as data reads it, marks the vulnerabilities known to be
// exploited, scores them from EPSS, and says what it found. host is read when the run did not read
// it. A match that cannot be made says why and what to do, and is never an
// error of the inventory: the packages are still listed.
func (m inventoryMatching) run(ctx context.Context, data *held.Run, host *osfingerprint.OSInfo, entries []softwarelist.SoftwareEntry) *vulnmatch.View {
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

	matcher, err := vulnmatch.New(source.Manager(), entries)
	if err != nil {
		return notDone(source.ID(), err.Error())
	}
	use := data.Read(ctx, source, host, func(r io.Reader) (dataset.Facts, error) {
		return source.Records(r, host, matcher.Add)
	})
	if use.NotDone != "" {
		return notDone(source.ID(), use.NotDone)
	}
	v := matcher.Result()
	v.Use = use
	v.MarkExploited(data.Exploited(ctx, host))
	v.MarkPredicted(predicted(ctx, data, host, v))
	return &v
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
