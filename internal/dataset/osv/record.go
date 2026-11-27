// internal/dataset/osv/record.go

package osv

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/vulnrecord"
)

// boundOf is the bound of a matching range each event of a kept range
// names: introduced is from its version, fixed before it, last affected up to
// it, and a limit ends the range there.
var boundOf = map[string]vulnrecord.Kind{
	eventIntroduced:   vulnrecord.From,
	eventFixed:        vulnrecord.Before,
	eventLastAffected: vulnrecord.UpTo,
	eventLimit:        vulnrecord.Limit,
}

// matching is r as the matcher reads it, each event of its ranges the bound
// it names. A kept record's ranges hold those four events alone, each naming
// one version, as validRange holds them.
func (r Record) matching() vulnrecord.Record {
	m := vulnrecord.Record{ID: r.ID, CVEs: r.CVEs, Published: r.Published, Modified: r.Modified, Advisory: r.Advisory, Rating: r.Rating}
	for _, s := range r.Severity {
		m.Scores = append(m.Scores, vulnrecord.Score{Type: s.Type, Score: s.Score})
	}
	for _, a := range r.Affected {
		affected := vulnrecord.Affected{Package: a.Package, Ecosystem: a.Ecosystem}
		for _, events := range a.Ranges {
			var bounds []vulnrecord.Bound
			for _, e := range events {
				for kind, version := range e {
					bounds = append(bounds, vulnrecord.Bound{Kind: boundOf[kind], Version: version})
				}
			}
			affected.Ranges = append(affected.Ranges, bounds)
		}
		m.Affected = append(m.Affected, affected)
	}
	return m
}

// maxEcosystemsSeen bounds how many of a dump's ecosystems are remembered to
// name in a refusal. Red Hat's dump of 2026-11-24 named 1,041.
const maxEcosystemsSeen = 4096

// record is the part of an OSV record that is read. A field it does not name
// is passed over, since OSV adds fields to the schema and its records.
type record struct {
	ID         string      `json:"id"`
	Modified   string      `json:"modified"`
	Published  string      `json:"published"`
	Withdrawn  string      `json:"withdrawn"`
	Summary    string      `json:"summary"`
	Aliases    []string    `json:"aliases"`
	Upstream   []string    `json:"upstream"`
	Severity   []Severity  `json:"severity"`
	Affected   []affected  `json:"affected"`
	References []reference `json:"references"`
}

// affected is one package a record names, in one ecosystem.
type affected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges []struct {
		Type   string  `json:"type"`
		Events []Event `json:"events"`
	} `json:"ranges"`
}

// Event is one event of a range: one of introduced, fixed, last_affected, or
// limit, and the version it is at.
type Event map[string]string

// Severity is a score a record carries, of the type it names, as CVSS_V3 or
// Ubuntu.
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// reference is an address a record gives, of the type it names.
type reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Record is a record as owatch keeps it: its identifier, the CVEs it names,
// when it was published and last modified, its advisory's address, the
// rating its title opens with where it has one, its scores, and the packages
// of the release it affects with their ranges.
type Record struct {
	ID        string     `json:"id"`
	CVEs      []string   `json:"cves"`
	Published string     `json:"published,omitempty"`
	Modified  string     `json:"modified"`
	Advisory  string     `json:"advisory,omitempty"`
	Rating    string     `json:"rating,omitempty"`
	Severity  []Severity `json:"severity,omitempty"`
	Affected  []Affected `json:"affected"`
}

// Affected is a package of the release a kept record affects, and the
// ranges of its versions that are affected.
type Affected struct {
	Package   string    `json:"package"`
	Ecosystem string    `json:"ecosystem"`
	Ranges    [][]Event `json:"ranges"`
}

// keptFor returns what is kept of r for rel, and nil when r affects nothing
// of rel. Every ecosystem r names is noted in seen, up to a bound. A score
// with no type, or no score, is left out: it cannot be shown as its source's,
// and one Ubuntu record of 2026-11-24 carried one beside a CVSS score. What
// is kept is held to the form valid judges.
func (r record) keptFor(rel release, seen map[string]bool) (*Record, error) {
	affected, err := r.affectedIn(rel, seen)
	if err != nil || len(affected) == 0 {
		return nil, err
	}
	k := Record{ID: r.ID, CVEs: r.cves(), Published: r.Published, Modified: r.Modified, Advisory: r.advisory(), Rating: r.rating(), Affected: affected}
	for _, s := range r.Severity {
		if s.Type != "" && s.Score != "" {
			k.Severity = append(k.Severity, s)
		}
	}
	if err := k.valid(rel); err != nil {
		return nil, err
	}
	return &k, nil
}

// affectedIn returns the packages r affects in rel, noting in seen, up to a
// bound, every ecosystem r names. A range of rel's that is not in the
// distribution's own order refuses r.
func (r record) affectedIn(rel release, seen map[string]bool) ([]Affected, error) {
	var affected []Affected
	for _, a := range r.Affected {
		eco := a.Package.Ecosystem
		if len(seen) < maxEcosystemsSeen {
			seen[eco] = true
		}
		if !rel.accepts(eco) {
			continue
		}
		ka := Affected{Package: a.Package.Name, Ecosystem: eco}
		for _, rg := range a.Ranges {
			if rg.Type != rangeEcosystem {
				return nil, fmt.Errorf("a range of %s is of type %q, not %s", dataset.Printable(a.Package.Name), dataset.Printable(rg.Type), rangeEcosystem)
			}
			ka.Ranges = append(ka.Ranges, rg.Events)
		}
		affected = append(affected, ka)
	}
	return affected, nil
}

// cves lists the CVEs r names, in its identifier, its upstream, and its
// aliases, once each and in order. A name that begins as a CVE's does is
// listed, so one that is not written as a CVE is refused by valid.
func (r record) cves() []string {
	cves := []string{}
	for _, name := range append(slices.Clone(r.Upstream), r.Aliases...) {
		if strings.HasPrefix(name, "CVE-") {
			cves = append(cves, name)
		}
	}
	if dataset.ValidCVE(r.ID) {
		cves = append(cves, r.ID)
	}
	slices.Sort(cves)
	return slices.Compact(cves)
}

// ratings are the words an advisory's title opens with, before a colon, to
// rate it, as Red Hat rates its advisories and AlmaLinux and Rocky Linux
// write theirs: "Important: kernel security update".
var ratings = []string{"Critical", "Important", "Moderate", "Low"}

// rating is the rating r's title opens with, as written, or none. It is the
// only part of the title kept.
func (r record) rating() string {
	word, _, found := strings.Cut(r.Summary, ": ")
	if found && slices.Contains(ratings, word) {
		return word
	}
	return ""
}

// advisory is the address of r's first advisory, or none.
func (r record) advisory() string {
	for _, ref := range r.References {
		if ref.Type == "ADVISORY" {
			return ref.URL
		}
	}
	return ""
}

// valid refuses k unless it is in the form the OSV schema gives a record, for
// rel: an identifier, the times it was modified and published, CVEs written
// as CVEs are, an HTTPS advisory, scores of text, and at least one package of
// rel, each with ranges that open with an introduced event and do not hold
// both a fixed and a last affected event.
func (k Record) valid(rel release) error {
	switch {
	case !identifier.MatchString(k.ID):
		return fmt.Errorf("%q is not a record's identifier", dataset.Printable(k.ID))
	case !validTime(k.Modified):
		return fmt.Errorf("the time it was modified, %q, is not an RFC 3339 time", dataset.Printable(k.Modified))
	case k.Published != "" && !validTime(k.Published):
		return fmt.Errorf("the time it was published, %q, is not an RFC 3339 time", dataset.Printable(k.Published))
	case k.CVEs == nil || !slices.IsSorted(k.CVEs) || len(slices.Compact(slices.Clone(k.CVEs))) != len(k.CVEs):
		return errors.New("its CVEs are not listed once each, in order")
	case len(k.Affected) == 0:
		return errors.New("it affects no package")
	}
	for _, cve := range k.CVEs {
		if !dataset.ValidCVE(cve) {
			return fmt.Errorf("%q is not a CVE identifier", dataset.Printable(cve))
		}
	}
	if err := validAdvisory(k.Advisory); err != nil {
		return err
	}
	if k.Rating != "" && !slices.Contains(ratings, k.Rating) {
		return fmt.Errorf("%q is not an advisory's rating", dataset.Printable(k.Rating))
	}
	for _, s := range k.Severity {
		if err := dataset.CheckText("a score's type", s.Type); err != nil {
			return err
		}
		if err := dataset.CheckText("a score", s.Score); err != nil {
			return err
		}
	}
	for _, a := range k.Affected {
		if err := a.valid(rel); err != nil {
			return err
		}
	}
	return nil
}

// valid refuses a package that is not named, is not of rel, or has a range
// that is not in the schema's form.
func (a Affected) valid(rel release) error {
	if err := dataset.CheckText("a package's name", a.Package); err != nil {
		return err
	}
	if !rel.accepts(a.Ecosystem) {
		return fmt.Errorf("%s is in %s, not %s", dataset.Printable(a.Package), dataset.Printable(a.Ecosystem), rel.name)
	}
	if len(a.Ranges) == 0 {
		return fmt.Errorf("%s has no range of versions", dataset.Printable(a.Package))
	}
	for _, events := range a.Ranges {
		if err := validRange(events); err != nil {
			return fmt.Errorf("%s: %w", dataset.Printable(a.Package), err)
		}
	}
	return nil
}

// validRange refuses a range that is not in the schema's form: every event
// one of those it names with a version, at least one introduced event, and
// not both a fixed and a last affected event.
func validRange(events []Event) error {
	count := map[string]int{}
	for _, e := range events {
		if len(e) != 1 {
			return fmt.Errorf("an event names %d versions, not one", len(e))
		}
		for kind, version := range e {
			switch kind {
			case eventIntroduced, eventFixed, eventLastAffected, eventLimit:
			default:
				return fmt.Errorf("%q is not an event of a range", dataset.Printable(kind))
			}
			if err := dataset.CheckText("a version", version); err != nil {
				return err
			}
			count[kind]++
		}
	}
	switch {
	case count[eventIntroduced] == 0:
		return errors.New("a range has no introduced event")
	case count[eventFixed] > 0 && count[eventLastAffected] > 0:
		return errors.New("a range has both fixed and last affected events")
	}
	return nil
}

// validAdvisory refuses an advisory address that is not HTTPS to a host. An
// empty one is a record that gives none.
func validAdvisory(address string) error {
	if address == "" {
		return nil
	}
	if err := dataset.CheckText("an advisory's address", address); err != nil {
		return err
	}
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("the advisory %q is not an HTTPS address of a host", dataset.Printable(address))
	}
	return nil
}

// validTime reports whether value is a time as RFC 3339 writes it.
func validTime(value string) bool {
	_, err := time.Parse(time.RFC3339Nano, value)
	return err == nil
}
