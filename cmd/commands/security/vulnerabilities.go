// cmd/commands/security/vulnerabilities.go

package security

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/tui"
	"github.com/papa0four/orkowatch/internal/vulnmatch"
)

// The status filter's option for a pair that could not be judged, beside
// those a match states, and the options of the known exploitation filter,
// which are also the bands the list is in when the catalog was read.
const (
	statusNotMatched  = "not matched"
	knownExploited    = "known exploited"
	notKnownExploited = "not in the catalog"
)

// vulnerabilitiesTab is the software's match against its dataset: one record
// per vulnerability of each affected package, then those that could not be
// judged. When the catalog of known-exploited vulnerabilities was read, those
// it lists come first, under their own heading, the most severe first, and
// the tab filters by it; the rest follow in their order, those with a fix
// available first, then the unfixed, then those not judged. It opens on
// those with a fix available, or on all when none has one, and filters by
// the severity the match gives each. With no match made it says why.
func vulnerabilitiesTab(v vulnmatch.View) tui.Tab {
	tab := tui.Tab{ID: tui.TabVulnerabilities, Name: "Vulnerabilities", Noun: "vulnerabilities"}
	if v.NotDone != "" {
		tab.Note = safeLines("Matching was not done: " + v.NotDone)
		return tab
	}
	against := matchedAgainst(v)
	exploitation := exploitationText(v.KnownExploited)
	banded := v.KnownExploited != nil && v.KnownExploited.NotDone == ""

	present := map[string]bool{}
	for _, l := range listedInOrder(v) {
		present[l.found.Severity.Level] = true
		tab.Records = append(tab.Records, vulnerabilityRecord(l.pkg, l.found, against, exploitation, banded))
	}
	for _, n := range v.NotMatched {
		present[vulnmatch.LevelNone] = true
		record := tui.Record{
			Title:    safeLines(n.ID + "  " + n.Package),
			Subtitle: statusNotMatched,
			Fields: []tui.SummaryLine{
				{Label: "package", Value: safeLines(n.Package)},
				{Label: "installed", Value: safeLines(n.Installed)},
				{Label: "not matched", Value: safeLines(n.Reason)},
				{Label: "matched against", Value: against},
			},
			Filters: [][]string{{statusNotMatched}, {vulnmatch.LevelNone}},
		}
		if banded {
			record.Band = notKnownExploited
			record.Filters = append(record.Filters, []string{notKnownExploited})
		}
		tab.Records = append(tab.Records, record)
	}

	start := vulnmatch.StatusFixAvailable
	if v.Counts.FixAvailable == 0 {
		start = tui.All
	}
	severities := []string{tui.All}
	for _, level := range vulnmatch.Levels() {
		if present[level] {
			severities = append(severities, level)
		}
	}
	tab.Filters = []tui.Filter{
		{Name: "status", Options: []string{tui.All, vulnmatch.StatusFixAvailable, vulnmatch.StatusUnfixed, statusNotMatched}, Start: start},
		{Name: "severity", Options: severities, Start: tui.All},
	}
	if banded {
		tab.Filters = append(tab.Filters, tui.Filter{Name: "known exploitation", Options: []string{tui.All, knownExploited, notKnownExploited}, Start: tui.All})
	}
	return tab
}

// listed is one vulnerability of an affected package.
type listed struct {
	pkg   vulnmatch.PackageMatches
	found vulnmatch.Vulnerability
}

// listedInOrder is every vulnerability of v's affected packages in the order
// the tab lists them: those known to be exploited first, the most severe
// first, then the rest with a fix available ahead of the unfixed, each in the
// order of its package and within it.
func listedInOrder(v vulnmatch.View) []listed {
	var all []listed
	for _, pkg := range v.Packages {
		for _, found := range pkg.Vulnerabilities {
			all = append(all, listed{pkg, found})
		}
	}
	slices.SortStableFunc(all, func(a, b listed) int {
		aKnown, bKnown := a.found.KnownExploited != nil, b.found.KnownExploited != nil
		switch {
		case aKnown != bKnown && aKnown:
			return -1
		case aKnown != bKnown:
			return 1
		case aKnown && a.found.Severity.Worse(b.found.Severity):
			return -1
		case aKnown && b.found.Severity.Worse(a.found.Severity):
			return 1
		case aKnown:
			return 0
		}
		return cmp.Compare(statusPlace(a.found.Status), statusPlace(b.found.Status))
	})
	return all
}

// exploitationText names the catalog of known-exploited vulnerabilities a
// match was marked from, its date, its state, and its attribution, or says
// why it was not read; it is empty for a match that predates the catalog.
func exploitationText(use *dataset.Use) string {
	switch {
	case use == nil:
		return ""
	case use.NotDone != "":
		return safeLines("not read: " + use.NotDone)
	}
	text := use.About()
	if use.Attribution != "" {
		text += "\n" + use.Attribution
	}
	return safeLines(text)
}

// matchedAgainst names the dataset a match was made against, its release, its
// date, and its state, on one line.
func matchedAgainst(v vulnmatch.View) string {
	return safeLines(v.About())
}

// vulnerabilityRecord is one vulnerability of an affected package as the tab
// shows it, with the catalog of known-exploited vulnerabilities as
// exploitation describes it, and in its band when banded.
func vulnerabilityRecord(pkg vulnmatch.PackageMatches, found vulnmatch.Vulnerability, against, exploitation string, banded bool) tui.Record {
	subtitle := found.Status
	if found.Fixed != "" {
		subtitle = "fix " + found.Fixed
	}
	if found.Severity.Label != "" {
		subtitle += "  " + found.Severity.Label
	}
	if found.KnownExploited != nil {
		subtitle = "exploited  " + subtitle
	}
	fields := []tui.SummaryLine{{Label: "package", Value: safeLines(pkg.Package)}}
	if len(pkg.Binaries) > 0 {
		fields = append(fields, tui.SummaryLine{Label: "installed packages built from it", Value: safeLines(strings.Join(pkg.Binaries, ", "))})
	}
	fields = append(fields,
		tui.SummaryLine{Label: "installed", Value: safeLines(pkg.Installed)},
		tui.SummaryLine{Label: "status", Value: found.Status})
	if found.Fixed != "" {
		fields = append(fields, tui.SummaryLine{Label: "fixed in", Value: safeLines(found.Fixed)})
	}
	fields = append(fields, tui.SummaryLine{Label: "severity", Value: safeLines(severityText(found.Severity))})
	if len(found.Scores) > 0 {
		scores := make([]string, 0, len(found.Scores))
		for _, s := range found.Scores {
			scores = append(scores, s.Type+": "+s.Score)
		}
		fields = append(fields, tui.SummaryLine{Label: "scores, as the records give them", Value: safeLines(strings.Join(scores, "\n"))})
	}
	if e := found.KnownExploited; e != nil {
		fields = append(fields, tui.SummaryLine{Label: "known to be exploited",
			Value: safeLines(fmt.Sprintf("added to the catalog %s\ndue date %s\nransomware use %s", e.Added, e.Due, e.Ransomware))})
	}
	fields = append(fields,
		tui.SummaryLine{Label: "records", Value: safeLines(strings.Join(found.Records, ", "))},
		tui.SummaryLine{Label: "matched against", Value: against})
	if exploitation != "" {
		fields = append(fields, tui.SummaryLine{Label: "known exploitation", Value: exploitation})
	}
	record := tui.Record{
		Title:    safeLines(found.ID + "  " + pkg.Package),
		Subtitle: safeLines(subtitle),
		Fields:   fields,
		Filters:  [][]string{{found.Status}, {found.Severity.Level}},
	}
	if banded {
		record.Band = notKnownExploited
		if found.KnownExploited != nil {
			record.Band = knownExploited
		}
		record.Filters = append(record.Filters, []string{record.Band})
	}
	return record
}

// severityText is a severity with what it rests on: the source's label and
// its basis, the level it is placed at when the label is another word, or
// that none is stated.
func severityText(s vulnmatch.Severity) string {
	if s.Label == "" {
		return vulnmatch.LevelNone
	}
	text := s.Label
	if !strings.EqualFold(s.Label, s.Level) {
		text += ", placed with " + s.Level
	}
	return text + " (" + s.Basis + ")"
}

// statusPlace orders the records: a fix available, then unfixed, then not
// matched.
func statusPlace(status string) int {
	switch status {
	case vulnmatch.StatusFixAvailable:
		return 0
	case vulnmatch.StatusUnfixed:
		return 1
	}
	return 2
}
