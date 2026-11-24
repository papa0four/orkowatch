// cmd/commands/security/browse.go

package security

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/security/audit"
	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/selection"
	"github.com/papa0four/orkowatch/internal/sockets"
	"github.com/papa0four/orkowatch/internal/softwarelist"
	"github.com/papa0four/orkowatch/internal/tui"
)

// BrowserSource is what a finished run holds for the browser to show. Audit,
// System, Software, Sockets, and Datasets are the projections a saved report
// carries, so a live run and a saved file are shown from the same data. Modules says how each
// module of an all run ended, which is what a tab with no data explains
// itself with; the audit command has none.
type BrowserSource struct {
	Title    string
	Audit    *audit.View
	System   *osfingerprint.SystemView
	Software *softwarelist.SoftwareView
	Sockets  *sockets.View
	Datasets *dataset.View
	Modules  []ModuleNote
	Text     string
}

// AuditSource is what the browser shows for an audit report: the projection
// a saved report carries and its full-report text. A live run and a saved
// report both build their source here, so the two cannot differ in what they
// take from the projection.
func AuditSource(title string, view audit.View, text string) BrowserSource {
	return BrowserSource{Title: title, Audit: &view, System: view.SystemInfo, Text: text}
}

// ModuleNote is how one module of an all run ended.
type ModuleNote struct {
	Name   string
	Result finding.Result
	Reason string
}

// BrowserReport builds what the results browser shows. Findings, System and
// Software are always offered, so every command opens the same layout: a source
// that was not collected has its tab with the reason, so the operator sees that
// nothing was collected rather than wondering whether the tab is missing.
// Every string the browser draws is made safe for the terminal here, through
// safeLines or, for evidence, render.EvidenceText, because the browser writes
// them straight to the terminal and any of them can carry text from the host
// or from a report file.
func BrowserReport(src BrowserSource) tui.Report {
	report := tui.Report{Title: safeLines(src.Title), Text: safeLines(src.Text), Start: landingTab(src.Modules)}
	if src.System != nil {
		report.Host = safeLines(src.System.Hostname)
	}

	if view := src.Audit; view != nil {
		report.When = safeLines(view.Timestamp)
		report.Summary = summaryLines(view)
		for _, check := range view.Results {
			if len(check.Conditions) == 0 {
				report.Items = append(report.Items, checkItem(check))
			}
			for _, condition := range check.Conditions {
				report.Items = append(report.Items, browserItem(condition))
			}
		}
	} else {
		report.FindingsNote = notRun(src.Modules, selection.NameAudit)
	}
	report.Tabs = sourceTabs(src)
	return report
}

// sourceTabs are the tabs beyond the findings, in the order they are offered.
func sourceTabs(src BrowserSource) []tui.Tab {
	var tabs []tui.Tab
	if src.System != nil {
		tabs = append(tabs, systemTab(*src.System))
	} else {
		tabs = append(tabs, tui.Tab{ID: tui.TabSystem, Name: "System", Note: notRun(src.Modules, selection.NameOS)})
	}

	if src.Software != nil {
		tabs = append(tabs, softwareTab(*src.Software))
	} else {
		tabs = append(tabs, tui.Tab{ID: tui.TabSoftware, Name: "Software", Note: notRun(src.Modules, selection.NameSoftware)})
	}

	if src.Sockets != nil {
		tabs = append(tabs, socketsTab(*src.Sockets))
	} else {
		tabs = append(tabs, tui.Tab{ID: tui.TabSockets, Name: "Sockets", Note: notRun(src.Modules, selection.NameListeners)})
	}

	// Only owatch data status reports the datasets, so their tab is offered
	// only by a report that holds them and every other report opens as it
	// did.
	if src.Datasets != nil {
		tabs = append(tabs, datasetsTab(*src.Datasets))
	}

	if src.Audit != nil {
		if tab, ok := attackTab(src.Audit); ok {
			tabs = append(tabs, tab)
		}
	}
	return tabs
}

// attackTab groups the run's findings by the ATT&CK technique each makes
// available, one record per technique in identifier order. It reports false
// when no finding carries one, so a run with none has no tab to be empty.
func attackTab(view *audit.View) (tui.Tab, bool) {
	type group struct {
		technique finding.Technique
		findings  []string
	}
	groups := make(map[string]*group)
	for _, check := range view.Results {
		for _, condition := range check.Conditions {
			def := condition.Finding
			if def == nil || condition.Result != finding.ResultFail {
				continue
			}
			for _, technique := range def.Attack {
				line := triggerBlock(condition, def, technique)
				g := groups[technique.ID]
				if g == nil {
					g = &group{technique: technique}
					groups[technique.ID] = g
				}
				g.findings = append(g.findings, line)
			}
		}
	}
	if len(groups) == 0 {
		return tui.Tab{}, false
	}

	ids := make([]string, 0, len(groups))
	for id := range groups {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	records := make([]tui.Record, 0, len(ids))
	for _, id := range ids {
		g := groups[id]
		tactics := strings.Join(g.technique.Tactics, ", ")
		records = append(records, tui.Record{
			Title:    safeLines(id + "  " + g.technique.Name),
			Subtitle: safeLines(tactics),
			Fields: []tui.SummaryLine{
				{Label: "tactics", Value: safeLines(tactics)},
				{Label: "page", Value: safeLines(g.technique.URL)},
				{Label: "mitigations", Value: safeLines(mitigationLines(g.technique.Mitigations))},
				{Label: "triggered by (" + strconv.Itoa(len(g.findings)) + " findings)", Value: safeLines(strings.Join(g.findings, "\n\n"))},
			},
		})
	}
	return tui.Tab{ID: tui.TabAttack, Name: "MITRE ATT&CK", Noun: "techniques", Records: records}, true
}

// landingTab is the tab the browser opens on. The findings, when the audit
// ran, since they are what a run is for. Otherwise the first module that did
// run, so a run of one module alone, or of several with the audit left out,
// opens on something it produced rather than on a tab that says nothing was
// collected. A module counts as run unless it was excluded; one that ran and
// failed still counts, and its tab says what went wrong.
func landingTab(modules []ModuleNote) string {
	tabs := map[string]string{
		selection.NameOS:        tui.TabSystem,
		selection.NameSoftware:  tui.TabSoftware,
		selection.NameListeners: tui.TabSockets,
		selection.NameDatasets:  tui.TabDatasets,
	}
	first := tui.TabFindings
	for _, m := range modules {
		switch tab, inventory := tabs[m.Name]; {
		case m.Result == finding.ResultNotSelected:
		case m.Name == selection.NameAudit:
			return tui.TabFindings
		case inventory && first == tui.TabFindings:
			first = tab
		}
	}
	return first
}

// notRun says why a source has no data: the run's own account of the module
// when it recorded one, as an all run does, and otherwise that the command
// never included it, with the command that collects it, which carries the
// module's name.
func notRun(modules []ModuleNote, name string) string {
	if note, ok := moduleNote(modules, name); ok {
		return note
	}
	return "not collected: this command does not run the " + name + " module. owatch all collects every source; owatch " +
		name + " collects only this one"
}

// triggerBlock describes one finding that made a technique available: its
// severity and title, the rule that failed, what that rule found, and the first
// of the evidence recorded for it, so the technique can be traced to the host
// observation behind it.
func triggerBlock(condition audit.ConditionView, def *audit.FindingView, technique finding.Technique) string {
	const shown = 3
	lines := []string{strings.ToUpper(def.Severity) + "  " + def.Title, "  rule: " + condition.Key}
	if condition.Reason != "" {
		lines = append(lines, "  found: "+condition.Reason)
	}
	for _, basis := range technique.Basis {
		lines = append(lines, "  associated because: "+basis)
	}
	for i, entry := range condition.Evidence {
		if i == shown {
			lines = append(lines, "  and "+strconv.Itoa(len(condition.Evidence)-shown)+" more evidence entries, listed under Findings")
			break
		}
		lines = append(lines, "  evidence: "+render.EvidenceText(entry))
	}
	return strings.Join(lines, "\n")
}

// moduleNote says why a module has no data: its result and reason as the run
// recorded them. It reports false when the run recorded nothing for the
// module, which is every module of an audit run.
func moduleNote(modules []ModuleNote, name string) (string, bool) {
	for _, m := range modules {
		if m.Name != name {
			continue
		}
		note := string(m.Result)
		if m.Reason != "" {
			note += ": " + m.Reason
		}
		return safeLines(note + "; nothing was collected"), true
	}
	return "", false
}

// systemTab is the host's fingerprint as one record, shown whole.
func systemTab(system osfingerprint.SystemView) tui.Tab {
	fields := []tui.SummaryLine{{Label: "os", Value: safeLines(system.OS)}}
	add := func(label, value string) {
		if value != "" {
			fields = append(fields, tui.SummaryLine{Label: label, Value: safeLines(value)})
		}
	}
	add("hostname", system.Hostname)
	add("platform", system.Platform)
	add("version", system.PlatformVersion)
	add("kernel", system.KernelVersion)
	add("architecture", system.Architecture)
	add("target", system.Target)
	extra := make([]string, 0, len(system.AdditionalInfo))
	for name := range system.AdditionalInfo {
		extra = append(extra, name)
	}
	slices.Sort(extra)
	for _, name := range extra {
		add(name, system.AdditionalInfo[name])
	}
	return tui.Tab{ID: tui.TabSystem, Name: "System", Records: []tui.Record{{
		Title:    safeLines(system.Hostname),
		Subtitle: safeLines(system.OS + " " + system.PlatformVersion),
		Fields:   fields,
	}}}
}

// datasetsTab is the store's datasets, one record each in the order status
// lists them, with what needs attention ahead of the rest. A store that holds
// nothing and has nothing that applies says so in place of the list.
func datasetsTab(v dataset.View) tui.Tab {
	tab := tui.Tab{ID: tui.TabDatasets, Name: "Datasets"}
	for _, r := range v.Datasets {
		var fields []tui.SummaryLine
		add := func(label, value string) {
			if value != "" {
				fields = append(fields, tui.SummaryLine{Label: label, Value: safeLines(value)})
			}
		}
		add("state", string(r.State))
		add("needs attention", r.Attention)
		add("reason", r.Reason)
		add("date of the data", r.DataDate)
		add("version", r.Version)
		add("fetched", r.Fetched)
		if r.Size > 0 {
			add("size", dataset.Size(r.Size))
		}
		add("source", r.Source)
		add("license", r.License)
		add("attribution", r.Attribution)
		add("store", v.Store)
		tab.Records = append(tab.Records, tui.Record{Title: safeLines(r.ID), Subtitle: safeLines(string(r.State)), Fields: fields})
	}
	if len(tab.Records) == 0 {
		tab.Note = safeLines("No dataset applies to this host, and the store at " + v.Store + " holds none.")
	}
	return tab
}

// socketsTab is the host's sockets, one record each, in the categories and
// order the text report lists them. A socket whose processes are missing or
// incomplete says why in its own record.
func socketsTab(v sockets.View) tui.Tab {
	var records []tui.Record
	for _, group := range [][]sockets.Socket{v.Internet, v.Raw, v.Unix, v.Packet} {
		for _, s := range group {
			records = append(records, socketRecord(s))
		}
	}
	tab := tui.Tab{ID: tui.TabSockets, Name: "Sockets", Records: records}
	if len(v.NotRead) > 0 {
		tab.Note = "not read on this platform: " + strings.Join(v.NotRead, ", ") + " sockets"
	}
	return tab
}

// socketRecord is one socket: its local end as the title, its protocol and
// state beside it, and every fact the reader recorded, in order.
func socketRecord(s sockets.Socket) tui.Record {
	fields := []tui.SummaryLine{{Label: "protocol", Value: safeLines(s.Protocol)}}
	add := func(label, value string) {
		if value != "" {
			fields = append(fields, tui.SummaryLine{Label: label, Value: safeLines(value)})
		}
	}
	add("type", s.Type)
	add("state", s.State)
	add("local", s.Local)
	add("remote", s.Remote)
	add("scope", s.Scope)
	add("owner", s.Owner)
	for _, p := range s.Processes {
		line := strconv.Itoa(p.PID)
		for _, part := range []string{p.Name, p.Path, p.User} {
			if part != "" {
				line += "  " + part
			}
		}
		add("process", line)
	}
	add("not attributed", s.Gap)
	add("inode", s.Inode)
	title := s.Local
	if title == "" {
		title = "unnamed, inode " + s.Inode
	}
	return tui.Record{
		Title:    safeLines(title),
		Subtitle: safeLines(strings.TrimSpace(s.Protocol + " " + s.State)),
		Fields:   fields,
	}
}

// softwareTab is the installed packages, one record each.
func softwareTab(software softwarelist.SoftwareView) tui.Tab {
	records := make([]tui.Record, 0, len(software.Packages))
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
		records = append(records, tui.Record{
			Title:    safeLines(pkg.Name),
			Subtitle: safeLines(pkg.Version),
			Fields:   fields,
		})
	}
	return tui.Tab{ID: tui.TabSoftware, Name: "Software", Records: records}
}

// checkItem is the row for a check that has no conditions to list, one that
// was excluded or could not evaluate any rule, so it does not vanish from the
// list. It carries the check's long name where the list has room for it and
// its short key in the filter column. A report written before checks had a
// key falls back to the long name there.
func checkItem(check audit.CheckView) tui.Item {
	short := check.Key
	if short == "" {
		short = check.Name
	}
	return tui.Item{
		Check:  safeLines(short),
		Key:    safeLines(check.Name),
		Result: check.Result,
		Reason: safeLines(check.Reason),
	}
}

// mitigationLines lists mitigations one to a line, as the technique's page
// lists them.
func mitigationLines(mitigations []finding.Mitigation) string {
	lines := make([]string, 0, len(mitigations))
	for _, m := range mitigations {
		lines = append(lines, audit.MitigationText(m))
	}
	return strings.Join(lines, "\n")
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
		setWeaknessAndCVSS(&item, def)
		item.Description = safeLines(def.Description)
		item.Impact = safeLines(def.Impact)
		item.Resolution = safeLines(def.Resolution)
		for _, ref := range def.References {
			item.References = append(item.References, safeLines(audit.ReferenceText(ref)))
		}
		seen := make(map[string]bool)
		for _, technique := range def.Attack {
			entry := audit.TechniqueText(technique)
			for _, basis := range technique.Basis {
				entry += "\n  basis: " + basis
			}
			item.Techniques = append(item.Techniques, safeLines(entry))
			for _, m := range technique.Mitigations {
				if !seen[m.ID] {
					seen[m.ID] = true
					item.Mitigations = append(item.Mitigations, safeLines(audit.MitigationText(m)))
				}
			}
		}
	}

	for _, entry := range condition.Evidence {
		item.Evidence = append(item.Evidence, render.EvidenceText(entry))
	}
	return item
}

// setWeaknessAndCVSS fills the parts of a finding's detail that state what kind
// of weakness it is and how it is scored: the CWE entry with MITRE's
// description, or the reason none fits, the registry's baseline, the score on
// this host with what it rests on, and which of them the severity is. The
// scores are rendered as the text report renders them.
func setWeaknessAndCVSS(item *tui.Item, def *audit.FindingView) {
	switch {
	case def.Weakness != nil:
		item.Weakness = safeLines(strings.Join(audit.WeaknessLines(*def.Weakness), "\n"))
		item.WeaknessAbout = safeLines(def.Weakness.Description + "\n" + def.Weakness.URL)
	case def.NoWeakness != "":
		item.Weakness = "none"
		item.WeaknessAbout = safeLines(def.NoWeakness)
	}
	item.SeverityBasis = audit.SeverityBasis(def)
	if def.CVSS != nil {
		item.CVSS = safeLines(strings.Join(audit.ScoreLines(*def.CVSS), "\n"))
		item.HostCVSS = safeLines(strings.Join(audit.HostScoreLines(def.Host), "\n"))
	}
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
