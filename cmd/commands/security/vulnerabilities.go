// cmd/commands/security/vulnerabilities.go

package security

import (
	"cmp"
	"slices"
	"strings"

	"github.com/papa0four/orkowatch/internal/dataset/osv"
	"github.com/papa0four/orkowatch/internal/tui"
	"github.com/papa0four/orkowatch/internal/vulnmatch"
)

// The options of the Vulnerabilities tab's filters beyond those a match
// states: a pair that could not be judged, and a vulnerability whose records
// state no severity label.
const (
	statusNotMatched = "not matched"
	noSeverity       = "none stated"
)

// severityRank orders the severity labels distributions state, most severe
// first, as Ubuntu's priorities run. A label not listed follows them.
var severityRank = []string{"critical", "high", "medium", "low", "negligible", "untriaged"}

// vulnerabilitiesTab is the software's match against its dataset: one record
// per vulnerability of each affected package, those with a fix available
// first, then the unfixed, then those that could not be judged. It opens on
// those with a fix available, or on all when none has one. With no match made
// it says why.
func vulnerabilitiesTab(v vulnmatch.View) tui.Tab {
	tab := tui.Tab{ID: tui.TabVulnerabilities, Name: "Vulnerabilities", Noun: "vulnerabilities"}
	if v.NotDone != "" {
		tab.Note = safeLines("Matching was not done: " + v.NotDone)
		return tab
	}
	against := safeLines(strings.Join([]string{v.Dataset, v.Release, "data of " + v.DataDate, v.State}, ", "))

	severities := map[string]bool{}
	for _, pkg := range v.Packages {
		for _, found := range pkg.Vulnerabilities {
			severity := severityLabel(found.Severity)
			severities[severity] = true
			tab.Records = append(tab.Records, vulnerabilityRecord(pkg, found, severity, against))
		}
	}
	for _, n := range v.NotMatched {
		severities[noSeverity] = true
		tab.Records = append(tab.Records, tui.Record{
			Title:    safeLines(n.ID + "  " + n.Package),
			Subtitle: statusNotMatched,
			Fields: []tui.SummaryLine{
				{Label: "package", Value: safeLines(n.Package)},
				{Label: "installed", Value: safeLines(n.Installed)},
				{Label: "not matched", Value: safeLines(n.Reason)},
				{Label: "matched against", Value: against},
			},
			Filters: []string{statusNotMatched, noSeverity},
		})
	}
	slices.SortStableFunc(tab.Records, func(a, b tui.Record) int {
		return cmp.Compare(statusPlace(a.Filters[0]), statusPlace(b.Filters[0]))
	})

	start := vulnmatch.StatusFixAvailable
	if v.Counts.FixAvailable == 0 {
		start = tui.All
	}
	tab.Filters = []tui.Filter{
		{Name: "status", Options: []string{tui.All, vulnmatch.StatusFixAvailable, vulnmatch.StatusUnfixed, statusNotMatched}, Start: start},
		{Name: "severity", Options: append([]string{tui.All}, severityOptions(severities)...), Start: tui.All},
	}
	return tab
}

// vulnerabilityRecord is one vulnerability of an affected package as the tab
// shows it.
func vulnerabilityRecord(pkg vulnmatch.PackageMatches, found vulnmatch.Vulnerability, severity, against string) tui.Record {
	subtitle := found.Status
	if found.Fixed != "" {
		subtitle = "fix " + found.Fixed
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
	if len(found.Severity) > 0 {
		scores := make([]string, 0, len(found.Severity))
		for _, s := range found.Severity {
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
		Filters:  []string{found.Status, severity},
	}
}

// severityLabel is the severity label the records state for a vulnerability:
// a score that is a single word, as Ubuntu's priorities are, and not a CVSS
// vector, which is a score and not a label. A vulnerability whose records
// state none, or more than one, is none stated, since a label is shown as
// its source gives it and never computed.
func severityLabel(scores []osv.Severity) string {
	label := ""
	for _, s := range scores {
		word := strings.ToLower(s.Score)
		if word == "" || strings.ContainsFunc(word, func(r rune) bool { return r < 'a' || r > 'z' }) {
			continue
		}
		if label != "" && label != word {
			return noSeverity
		}
		label = word
	}
	return cmp.Or(label, noSeverity)
}

// severityOptions lists the severity labels present, most severe first, then
// any other in name order, then none stated.
func severityOptions(present map[string]bool) []string {
	var options []string
	for _, label := range severityRank {
		if present[label] {
			options = append(options, label)
		}
	}
	var others []string
	for label := range present {
		if !slices.Contains(severityRank, label) && label != noSeverity {
			others = append(others, label)
		}
	}
	slices.Sort(others)
	options = append(options, others...)
	if present[noSeverity] {
		options = append(options, noSeverity)
	}
	return options
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
