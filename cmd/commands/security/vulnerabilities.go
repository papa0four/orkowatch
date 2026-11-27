// cmd/commands/security/vulnerabilities.go

package security

import (
	"fmt"
	"strings"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/epss"
	"github.com/papa0four/orkowatch/internal/tone"
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
// judged, in the order every view lists vulnerabilities. When the catalog of
// known-exploited vulnerabilities was read, those it lists come first, under
// their own heading and in the critical color, listed whichever status is
// chosen, and the tab filters by it; the rest follow under theirs, then those
// not judged. It opens on those with a
// fix available, or on all when none has one, and filters by the severity
// the match gives each. With no match made it says why.
func vulnerabilitiesTab(v vulnmatch.View) tui.Tab {
	tab := tui.Tab{ID: tui.TabVulnerabilities, Name: "Vulnerabilities", Noun: "vulnerabilities"}
	if v.NotDone != "" {
		tab.Note = safeLines("Matching was not done: " + v.NotDone)
		return tab
	}
	against := matchedAgainst(v)
	banded := v.KnownExploited != nil && v.KnownExploited.NotDone == ""
	data := matchData{view: v, against: against, exploitation: useText(v.KnownExploited), prediction: useText(v.ExploitPrediction), banded: banded}

	present := map[string]bool{}
	for _, l := range v.InOrder() {
		present[l.Vulnerability.Severity.Level] = true
		tab.Records = append(tab.Records, vulnerabilityRecord(l.Package, l.Vulnerability, data))
	}
	for _, n := range v.NotMatched {
		present[vulnmatch.LevelNone] = true
		record := tui.Record{
			Title:    safeLines(n.ID + "  " + n.Package),
			Subtitle: tui.Plain(statusNotMatched),
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
	tones := map[string]tone.Tone{}
	for _, level := range vulnmatch.Levels() {
		if present[level] {
			severities = append(severities, level)
			tones[level] = tone.ForSeverity(level)
		}
	}
	tab.Filters = []tui.Filter{
		{Name: "status", Options: statusOptions(v), Start: start},
		{Name: "severity", Options: severities, Start: tui.All, Tones: tones},
	}
	if banded {
		tab.Alert = knownExploited
		tab.Filters[0].Spares = knownExploited
		tab.Filters = append(tab.Filters, tui.Filter{Name: "known exploitation", Options: []string{tui.All, knownExploited, notKnownExploited}, Start: tui.All})
	}
	return tab
}

// / statusOptions are the statuses the tab filters by: those every match has,
// and an open tracking bug when the match holds one, which only a source of
// tracking bugs gives.
func statusOptions(v vulnmatch.View) []string {
	options := []string{tui.All, vulnmatch.StatusFixAvailable, vulnmatch.StatusUnfixed}
	if v.Counts.Tracked > 0 {
		options = append(options, vulnmatch.StatusTracked)
	}
	return append(options, statusNotMatched)
}

// useText names the dataset a match was marked or scored from and its
// attribution, or says why it was not read; it is empty for a match that
// predates the dataset.
func useText(use *dataset.Use) string {
	if use == nil {
		return ""
	}
	return safeLines(strings.Join(use.Lines(), "\n"))
}

// matchedAgainst names the dataset a match was made against, its release, its
// date, and its state, on one line.
func matchedAgainst(v vulnmatch.View) string {
	return safeLines(v.About())
}

// matchData is what every record of the tab shows of the match as a whole:
// the match, the dataset it was made against, the catalog of known-exploited
// vulnerabilities and the EPSS scores file as their detail describes them,
// and whether the records are banded by the catalog.
type matchData struct {
	view                              vulnmatch.View
	against, exploitation, prediction string
	banded                            bool
}

// vulnerabilityRecord is one vulnerability of an affected package as the tab
// shows it, with data's description of the match, and in its band when the
// records are banded. Its subtitle is in the order the tab lists by: known
// exploitation, severity, the EPSS score, then the status, with the known
// exploitation and the severity in their tones.
func vulnerabilityRecord(pkg vulnmatch.PackageMatches, found vulnmatch.Vulnerability, data matchData) tui.Record {
	var parts []tui.Span
	if found.KnownExploited != nil {
		parts = append(parts, tui.Span{Text: "exploited", Tone: tone.KnownExploited})
	}
	if found.Severity.Label != "" {
		parts = append(parts, tui.Span{Text: safeLines(found.Severity.Label), Tone: tone.ForSeverity(found.Severity.Level)})
	}
	if word := data.view.PredictionWord(found); word != "" {
		parts = append(parts, tui.Span{Text: word})
	}
	if found.Fixed != "" {
		parts = append(parts, tui.Span{Text: safeLines("fix " + found.Fixed)})
	} else {
		parts = append(parts, tui.Span{Text: found.Status})
	}
	var subtitle tui.Line
	for i, part := range parts {
		if i > 0 {
			subtitle = append(subtitle, tui.Span{Text: "  "})
		}
		subtitle = append(subtitle, part)
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
	fields = append(fields, tui.SummaryLine{Label: "severity", Value: safeLines(severityText(found.Severity)), Tone: tone.ForSeverity(found.Severity.Level)})
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
	if p := found.ExploitPrediction; p != nil {
		fields = append(fields, tui.SummaryLine{Label: "exploit prediction", Value: fmt.Sprintf(
			"score %s, the probability that it will be exploited in the wild in the next 30 days\n"+
				"percentile %s, the proportion of all scored vulnerabilities with the same score or lower",
			epss.Percent(p.Score), epss.Percent(p.Percentile))})
	}
	fields = append(fields,
		tui.SummaryLine{Label: "records", Value: safeLines(strings.Join(found.Records, ", "))},
		tui.SummaryLine{Label: "matched against", Value: data.against})
	if data.exploitation != "" {
		fields = append(fields, tui.SummaryLine{Label: "known exploitation", Value: data.exploitation})
	}
	if data.prediction != "" {
		fields = append(fields, tui.SummaryLine{Label: "exploit prediction data", Value: data.prediction})
	}
	record := tui.Record{
		Title:    safeLines(found.ID + "  " + pkg.Package),
		Subtitle: subtitle,
		Fields:   fields,
		Filters:  [][]string{{found.Status}, {found.Severity.Level}},
	}
	if data.banded {
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
