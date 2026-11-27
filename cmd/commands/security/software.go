// cmd/commands/security/software.go

package security

import (
	"fmt"
	"strings"

	"github.com/papa0four/orkowatch/internal/softwarelist"
	"github.com/papa0four/orkowatch/internal/tone"
	"github.com/papa0four/orkowatch/internal/tui"
	"github.com/papa0four/orkowatch/internal/vulnmatch"
)

// The Software tab's filter by what was matched to each package, its options
// beyond all, and the key that switches between all and the affected.
const (
	matchedFilter     = "vulnerabilities"
	optionAffected    = "affected"
	optionFixable     = "fix available"
	affectedSwitchKey = "a"
)

// softwareTab is the installed packages, one record each. When the software
// was matched, each package of the manager matched shows how many
// vulnerabilities it has with a fix available and unfixed and the worst
// severity among them, lists them in its detail, and the tab filters to the
// affected packages or those with a fix available; a switches between all
// and the affected. A package is joined to its match by the name and version
// the records use, so the binaries of one source share its vulnerabilities.
// With no match made, the tab is the inventory, and each package says why.
func softwareTab(software softwarelist.SoftwareView, vulns *vulnmatch.View) tui.Tab {
	tab := tui.Tab{ID: tui.TabSoftware, Name: "Software"}
	matches := map[[2]string]vulnmatch.PackageMatches{}
	matched := vulns != nil && vulns.NotDone == ""
	if matched {
		for _, pkg := range vulns.Packages {
			matches[[2]string{pkg.Package, pkg.Installed}] = pkg
		}
		tab.Filters = []tui.Filter{{Name: matchedFilter, Options: []string{tui.All, optionAffected, optionFixable}, Start: tui.All}}
		tab.Switch = tui.Switch{Key: affectedSwitchKey, Filter: matchedFilter, A: tui.All, B: optionAffected, Hint: "affected or all"}
	}

	tab.Records = make([]tui.Record, 0, len(software.Packages))
	for _, pkg := range software.Packages {
		fields := []tui.SummaryLine{{Label: "name", Value: safeLines(pkg.Name)}}
		for _, field := range []tui.SummaryLine{
			{Label: "version", Value: pkg.Version},
			{Label: "architecture", Value: pkg.Architecture},
			{Label: "package manager", Value: pkg.Manager},
			{Label: "source package", Value: pkg.Source},
			{Label: "source version", Value: pkg.SourceVersion},
		} {
			if field.Value != "" {
				fields = append(fields, tui.SummaryLine{Label: field.Label, Value: safeLines(field.Value)})
			}
		}
		record := tui.Record{Title: safeLines(pkg.Name), Subtitle: tui.Plain(safeLines(pkg.Version))}
		switch {
		case matched && pkg.Manager == vulns.Order:
			name, version := vulnmatch.Named(pkg)
			found, affected := matches[[2]string{name, version}]
			record.Filters = [][]string{matchedOptions(found, affected)}
			if affected {
				summary := packageSummary(found)
				record.Subtitle = append(tui.Plain(safeLines(pkg.Version+"  ")), summary...)
				fields = append(fields,
					tui.SummaryLine{Label: "vulnerabilities", Value: summary.String()},
					tui.SummaryLine{Label: "matched against " + matchedAgainst(*vulns), Value: safeLines(vulnerabilityLines(found))})
			} else {
				fields = append(fields, tui.SummaryLine{Label: "vulnerabilities", Value: "none matched; this does not say the package has none"})
			}
		case matched:
			record.Filters = [][]string{nil}
		case vulns != nil:
			fields = append(fields, tui.SummaryLine{Label: "vulnerabilities", Value: safeLines("Matching was not done: " + vulns.NotDone)})
		}
		record.Fields = fields
		tab.Records = append(tab.Records, record)
	}
	return tab
}

// matchedOptions are the options of the Software tab's filter a package
// falls under: affected when it has any vulnerability, and fix available
// when one of them has a fix.
func matchedOptions(found vulnmatch.PackageMatches, affected bool) []string {
	if !affected {
		return nil
	}
	options := []string{optionAffected}
	for _, v := range found.Vulnerabilities {
		if v.Status == vulnmatch.StatusFixAvailable {
			return append(options, optionFixable)
		}
	}
	return options
}

// packageSummary counts a package's vulnerabilities, those with a fix,
// those unfixed, and those with a tracking bug open, and names the worst
// severity among them, in its tone.
func packageSummary(found vulnmatch.PackageMatches) tui.Line {
	fixable, unfixed, tracked := 0, 0, 0
	worst := vulnmatch.Severity{Level: vulnmatch.LevelNone}
	for _, v := range found.Vulnerabilities {
		switch v.Status {
		case vulnmatch.StatusFixAvailable:
			fixable++
		case vulnmatch.StatusTracked:
			tracked++
		default:
			unfixed++
		}
		if v.Severity.Worse(worst) {
			worst = v.Severity
		}
	}
	var parts []string
	if fixable > 0 {
		parts = append(parts, fmt.Sprintf("%d fixable", fixable))
	}
	if unfixed > 0 {
		parts = append(parts, fmt.Sprintf("%d unfixed", unfixed))
	}
	if tracked > 0 {
		parts = append(parts, fmt.Sprintf("%d with a tracking bug open", tracked))
	}
	summary := tui.Plain(strings.Join(parts, ", "))
	if worst.Level != vulnmatch.LevelNone {
		summary = append(summary, tui.Span{Text: "; worst "}, tui.Span{Text: safeLines(worst.Label), Tone: tone.ForSeverity(worst.Level)})
	}
	return summary
}

// vulnerabilityLines lists a package's vulnerabilities, one a line, in the
// match's order: those with a fix first, then by severity.
func vulnerabilityLines(found vulnmatch.PackageMatches) string {
	lines := make([]string, 0, len(found.Vulnerabilities))
	for _, v := range found.Vulnerabilities {
		line := v.ID + "  " + v.Status
		if v.Fixed != "" {
			line = v.ID + "  fix " + v.Fixed
		}
		if v.Severity.Label != "" {
			line += "  " + v.Severity.Label
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}
