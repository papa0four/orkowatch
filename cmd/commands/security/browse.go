// cmd/commands/security/browse.go

package security

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/tui"
)

// BrowserReport builds what the results browser shows from a finished audit.
// view is nil when the audit did not run, which leaves the browser only the
// plain report in text to page through. Every string the browser draws is
// made safe for the terminal here, through safeLines or, for evidence,
// render.EvidenceText, because the browser writes them straight to the
// terminal and any of them can carry text from the host or from a report
// file.
func BrowserReport(title string, view *audit.View, system *osfingerprint.SystemView, text string) tui.Report {
	report := tui.Report{Title: safeLines(title), Text: safeLines(text)}
	if system != nil {
		report.Host = safeLines(system.Hostname)
	}
	if view == nil {
		return report
	}

	report.When = safeLines(view.Timestamp)
	report.Summary = summaryLines(view)
	for _, check := range view.Results {
		for _, condition := range check.Conditions {
			report.Items = append(report.Items, browserItem(condition))
		}
	}
	return report
}

// browserItem converts one condition. Its check is named by the rule key's
// prefix, the short form the browser's filter column has room for.
func browserItem(condition audit.ConditionView) tui.Item {
	check, _, _ := strings.Cut(condition.Key, ".")
	item := tui.Item{
		Check:  safeLines(check),
		Key:    safeLines(condition.Key),
		Result: condition.Result,
		Reason: safeLines(condition.Reason),
	}

	if def := condition.Finding; def != nil {
		item.Severity = strings.ToUpper(def.Severity)
		item.Title = safeLines(def.Title)
		for _, category := range def.Categories {
			item.Categories = append(item.Categories, safeLines(category))
		}
		item.Description = safeLines(def.Description)
		item.Impact = safeLines(def.Impact)
		item.Resolution = safeLines(def.Resolution)
		for _, ref := range def.References {
			item.References = append(item.References, safeLines(audit.ReferenceText(ref)))
		}
	}

	for _, entry := range condition.Evidence {
		item.Evidence = append(item.Evidence, render.EvidenceText(entry))
	}
	return item
}

// summaryLines lists the run's figures as the audit already counted them:
// checks by result, conditions, findings by severity, and duration.
func summaryLines(view *audit.View) []tui.SummaryLine {
	summary := view.Summary
	lines := []tui.SummaryLine{{Label: "checks", Value: strconv.Itoa(summary.TotalChecks)}}
	for _, result := range finding.Results() {
		if count := summary.Checks[result]; count > 0 {
			lines = append(lines, tui.SummaryLine{Label: "  " + string(result), Value: strconv.Itoa(count)})
		}
	}
	lines = append(lines,
		tui.SummaryLine{Label: "conditions", Value: strconv.Itoa(summary.TotalConditions)},
		tui.SummaryLine{Label: "findings", Value: strconv.Itoa(summary.TotalFindings)},
	)

	severities := finding.Severities()
	for i := len(severities) - 1; i >= 0; i-- {
		if count := summary.Findings[severities[i]]; count > 0 {
			lines = append(lines, tui.SummaryLine{Label: "  " + strings.ToLower(severities[i]), Value: strconv.Itoa(count)})
		}
	}
	if view.FindingsSuppressed > 0 {
		lines = append(lines, tui.SummaryLine{Label: "suppressed", Value: fmt.Sprintf("%d below %s", view.FindingsSuppressed, view.MinSeverityApplied)})
	}
	return append(lines, tui.SummaryLine{Label: "duration", Value: shortDuration(view.Duration)})
}

// shortDuration rounds a duration the report spelled to the nanosecond, which
// is more than the summary column has room for. A value that does not parse,
// as one from a hand-edited report file might not, is shown as written.
func shortDuration(spelled string) string {
	d, err := time.ParseDuration(spelled)
	if err != nil {
		return safeLines(spelled)
	}
	return d.Round(time.Millisecond).String()
}

// safeLines applies render.HostText to each line of s, so text of several
// lines keeps its line breaks while no line can carry a control character
// to the terminal.
func safeLines(s string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = render.HostText(strings.TrimSuffix(line, "\r"))
	}
	return strings.Join(lines, "\n")
}
