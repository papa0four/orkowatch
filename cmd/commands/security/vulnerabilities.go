// cmd/commands/security/vulnerabilities.go

package security

import (
	"cmp"
	"slices"
	"strings"

	"github.com/papa0four/orkowatch/internal/tui"
	"github.com/papa0four/orkowatch/internal/vulnmatch"
)

// statusNotMatched is the status filter's option for a pair that could not
// be judged, beside those a match states.
const statusNotMatched = "not matched"

// vulnerabilitiesTab is the software's match against its dataset: one record
// per vulnerability of each affected package, those with a fix available
// first, then the unfixed, then those that could not be judged. It opens on
// those with a fix available, or on all when none has one, and filters by
// the severity the match gives each. With no match made it says why.
func vulnerabilitiesTab(v vulnmatch.View) tui.Tab {
	tab := tui.Tab{ID: tui.TabVulnerabilities, Name: "Vulnerabilities", Noun: "vulnerabilities"}
	if v.NotDone != "" {
		tab.Note = safeLines("Matching was not done: " + v.NotDone)
		return tab
	}
	against := matchedAgainst(v)

	present := map[string]bool{}
	for _, pkg := range v.Packages {
		for _, found := range pkg.Vulnerabilities {
			present[found.Severity.Level] = true
			tab.Records = append(tab.Records, vulnerabilityRecord(pkg, found, against))
		}
	}
	for _, n := range v.NotMatched {
		present[vulnmatch.LevelNone] = true
		tab.Records = append(tab.Records, tui.Record{
			Title:    safeLines(n.ID + "  " + n.Package),
			Subtitle: statusNotMatched,
			Fields: []tui.SummaryLine{
				{Label: "package", Value: safeLines(n.Package)},
				{Label: "installed", Value: safeLines(n.Installed)},
				{Label: "not matched", Value: safeLines(n.Reason)},
				{Label: "matched against", Value: against},
			},
			Filters: []string{statusNotMatched, vulnmatch.LevelNone},
		})
	}
	slices.SortStableFunc(tab.Records, func(a, b tui.Record) int {
		return cmp.Compare(statusPlace(a.Filters[0]), statusPlace(b.Filters[0]))
	})

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
	return tab
}

// matchedAgainst names the dataset a match was made against, its release, its
// date, and its state, on one line.
func matchedAgainst(v vulnmatch.View) string {
	return safeLines(strings.Join([]string{v.Dataset, v.Release, "data of " + v.DataDate, v.State}, ", "))
}

// vulnerabilityRecord is one vulnerability of an affected package as the tab
// shows it.
func vulnerabilityRecord(pkg vulnmatch.PackageMatches, found vulnmatch.Vulnerability, against string) tui.Record {
	subtitle := found.Status
	if found.Fixed != "" {
		subtitle = "fix " + found.Fixed
	}
	if found.Severity.Label != "" {
		subtitle += "  " + found.Severity.Label
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
	fields = append(fields,
		tui.SummaryLine{Label: "records", Value: safeLines(strings.Join(found.Records, ", "))},
		tui.SummaryLine{Label: "matched against", Value: against})
	return tui.Record{
		Title:    safeLines(found.ID + "  " + pkg.Package),
		Subtitle: safeLines(subtitle),
		Fields:   fields,
		Filters:  []string{found.Status, found.Severity.Level},
	}
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
