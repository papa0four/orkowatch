// internal/tui/browser_test.go

package tui

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

var escapes = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func plain(s string) string { return escapes.ReplaceAllString(s, "") }

func sidebarReport(checks int) Report {
	var items []Item
	for i := 0; i < checks; i++ {
		items = append(items, Item{Check: fmt.Sprintf("check%d", i), Key: fmt.Sprintf("check%d.rule", i),
			Result: "fail", Severity: "HIGH", Title: "a finding"})
	}
	return Report{
		Title:   "owatch all",
		Items:   items,
		Summary: []SummaryLine{{Label: "checks", Value: "3"}},
		Tabs: []Tab{
			{ID: TabSystem, Name: "System", Note: "system note"},
			{ID: TabSoftware, Name: "Software", Note: "software note"},
		},
	}
}

func press(b browser, key string) browser {
	m, _ := b.onKey(tea.KeyPressMsg{Code: rune(key[0]), Text: key})
	return m.(browser)
}

// pressCode presses a key that types nothing, such as esc or enter.
func pressCode(b browser, code rune) browser {
	m, _ := b.onKey(tea.KeyPressMsg{Code: code})
	return m.(browser)
}

// keep types query into the search and keeps it with enter.
func keep(b browser, query string) browser {
	b = press(b, "/")
	for _, r := range query {
		b = press(b, string(r))
	}
	return pressCode(b, tea.KeyEnter)
}

func sized(b browser, width, height int) browser {
	b.width, b.height = width, height
	b.layout()
	b.showSelected()
	return b
}

// The left pane stays on every source, lists them with the key that opens each,
// and says the findings summary does not apply to a source that has none.
func TestSidebarPersistsOnEverySource(t *testing.T) {
	b := sized(newBrowser(sidebarReport(2)), 100, 30)
	for _, tab := range []string{"f", "o", "s"} {
		b = press(b, tab)
		frame := plain(b.render())
		for _, want := range []*regexp.Regexp{
			regexp.MustCompile(`f\s+Findings`), regexp.MustCompile(`o\s+System`), regexp.MustCompile(`s\s+Software`), regexp.MustCompile(`summary`),
		} {
			if !want.MatchString(frame) {
				t.Errorf("after %q the left pane lacks %q:\n%s", tab, want, frame)
			}
		}
	}
	frame := plain(b.render())
	if !strings.Contains(frame, "n/a") || !strings.Contains(frame, "software note") {
		t.Errorf("a source with no findings shows no n/a and its note:\n%s", frame)
	}
}

// A left pane taller than the window scrolls with the cursor, and the keys
// that open a source still work while it has the keyboard.
func TestSidebarScrollsAndKeepsHotKeys(t *testing.T) {
	b := sized(newBrowser(sidebarReport(20)), 100, 14)
	b.focus = focusFilters
	for range 18 {
		b.onFilterKey("down")
	}
	if b.sideTop == 0 {
		t.Fatalf("the pane did not scroll to keep the cursor at row %d in view", b.filterCursor)
	}
	lines, cursorLine := b.sidebarLines()
	if cursorLine < b.sideTop || cursorLine >= b.sideTop+b.bodyHeight() || len(lines) <= b.bodyHeight() {
		t.Fatalf("cursor line %d is outside the window starting at %d of %d lines", cursorLine, b.sideTop, len(lines))
	}

	b = press(b, "s")
	if b.tabs[b.active].id != TabSoftware {
		t.Fatalf("the s key did not open Software from the left pane; active %q", b.tabs[b.active].id)
	}
	if lines, cursorLine = b.sidebarLines(); cursorLine < b.sideTop || cursorLine >= b.sideTop+b.bodyHeight() {
		t.Fatalf("after the jump the cursor line %d is outside the window at %d of %d", cursorLine, b.sideTop, len(lines))
	}
}

// Enter on a source in the left pane opens it and leaves the keyboard there.
func TestSidebarEnterOpensSource(t *testing.T) {
	b := sized(newBrowser(sidebarReport(1)), 100, 30)
	b.focus = focusFilters
	b.filterCursor = 1
	b.onFilterKey("enter")
	if b.tabs[b.active].id != TabSystem || b.focus != focusFilters {
		t.Fatalf("enter opened %q with focus %v", b.tabs[b.active].id, b.focus)
	}
}

// A window too narrow for the left pane falls back to the tab bar, so the
// sources are still listed.
func TestNarrowWindowUsesTabBar(t *testing.T) {
	b := sized(newBrowser(sidebarReport(1)), 40, 20)
	if frame := plain(b.render()); !strings.Contains(frame, "o System") {
		t.Errorf("no way to see the sources at a narrow width:\n%s", frame)
	}
}

// A report that names a tab to start on opens there, with that source in the
// left pane's selection, and one that names none opens on the findings.
func TestStartTab(t *testing.T) {
	r := sidebarReport(2)
	if b := newBrowser(r); b.tabs[b.active].id != TabFindings {
		t.Errorf("no Start opened on %q", b.tabs[b.active].id)
	}
	r.Start = TabSoftware
	b := sized(newBrowser(r), 100, 30)
	if b.tabs[b.active].id != TabSoftware || b.filterCursor != b.active {
		t.Errorf("Start software opened on %q with the left pane on row %d", b.tabs[b.active].id, b.filterCursor)
	}
	r.Start = "no-such-tab"
	if b := newBrowser(r); b.tabs[b.active].id != TabFindings {
		t.Errorf("an unknown Start opened on %q", b.tabs[b.active].id)
	}
}

// A finding's detail says what raised it: the rule, what it found, its
// evidence, its severity and the techniques it makes available.
func TestFindingDetailSaysWhatTriggeredIt(t *testing.T) {
	r := sidebarReport(0)
	r.Items = []Item{{Check: "users", Key: "users.no_password_required", Result: "fail", Severity: "HIGH",
		Title: "Account may have a blank password", Reason: "blank password permitted",
		Evidence:   []string{"- alice"},
		Techniques: []string{"T1078.003 Local Accounts (Persistence)"}}}
	b := sized(newBrowser(r), 120, 40)
	detail := plain(b.detail.View())
	for _, want := range []string{"triggered by", "rule      users.no_password_required", "found     blank password permitted",
		"evidence  1 entry", "severity  HIGH", "attack    T1078.003, because this rule failed"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail is missing %q:\n%s", want, detail)
		}
	}
}

// A search finds a finding by its scores: the CVSS-BE label and a modified
// metric find only the finding the host's evidence modified, and the baseline's
// label finds both.
func TestSearchFindsScores(t *testing.T) {
	r := sidebarReport(0)
	r.Items = []Item{
		{Check: "ssh", Key: "ssh.moved", Result: "fail", Severity: "HIGH", Title: "moved",
			CVSS:          "9.3 CRITICAL  CVSS-B v4.0, baseline for the condition",
			HostCVSS:      "8.6 HIGH  CVSS-BE v4.0\nMAV:L from listening loopback-only on 1 of 1 subject",
			SeverityBasis: "the CVSS-BE severity on this host; the registry rates the rule CRITICAL"},
		{Check: "ssh", Key: "ssh.kept", Result: "fail", Severity: "CRITICAL", Title: "kept",
			CVSS:          "9.3 CRITICAL  CVSS-B v4.0, baseline for the condition",
			HostCVSS:      "none; the evidence recorded on this host modified no metric, so the CVSS-B baseline stands",
			SeverityBasis: "the registry's rating for this rule"},
	}
	b := sized(newBrowser(r), 120, 40)
	for query, want := range map[string][]int{"CVSS-BE": {0}, "mav:l": {0}, "cvss-b v4.0": {0, 1}, "registry's rating": {1}} {
		b.query = query
		b.refilterFindings()
		if !slices.Equal(b.visible, want) {
			t.Errorf("searching %q leaves %v, want %v", query, b.visible, want)
		}
	}
}

// The detail pane shows the baseline and the score on this host under their
// own headings and says what the severity rests on, and at a narrow and a wide
// window no line runs past the pane.
func TestFindingDetailShowsBothScores(t *testing.T) {
	r := sidebarReport(0)
	r.Items = []Item{{Check: "ssh", Key: "ssh.root_login_permitted", Result: "fail", Severity: "HIGH",
		Title: "Root login over SSH is permitted", Evidence: []string{"- listening=loopback-only"},
		SeverityBasis: "the CVSS-BE severity on this host; the registry rates the rule CRITICAL",
		CVSS:          "9.3 CRITICAL  CVSS-B v4.0, baseline for the condition, not measured on this host  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N\ncalculator: https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		HostCVSS: "8.6 HIGH  CVSS-BE v4.0, Modified Base metrics derived from evidence recorded on this host  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MAV:L\n" +
			"MAV:L from listening loopback-only on 1 of 1 subject: sshd listens only on loopback addresses\n" +
			"  Implementation Guide, Modified Attack Vector (MAV): \"the service is exposed locally\""}}
	for _, width := range []int{50, 160} {
		b := sized(newBrowser(r), width, 60)
		text, _ := b.detailText(r.Items[0])
		detail := plain(text)
		for _, want := range []string{"CVSS baseline", "9.3 CRITICAL", "CVSS on this host", "8.6 HIGH", "CVSS-BE", "MAV:L from listening",
			"severity  HIGH, the CVSS-BE severity on this host; the registry rates the rule CRITICAL"} {
			if !strings.Contains(strings.Join(strings.Fields(detail), " "), strings.Join(strings.Fields(want), " ")) {
				t.Errorf("at width %d the detail lacks %q:\n%s", width, want, detail)
			}
		}
		for _, line := range strings.Split(detail, "\n") {
			if w := lipgloss.Width(line); w > b.mainWidth() {
				t.Errorf("at width %d a line is %d wide, past the pane's %d: %q", width, w, b.mainWidth(), line)
			}
		}
	}
}

// A kept search is cleared by esc on the list and on the left pane, on the
// findings tab and on a record tab. From the detail pane the first esc goes
// back to the list and the second clears. The footer names the key only while
// esc would clear a search.
func TestEscClearsAKeptSearch(t *testing.T) {
	r := sidebarReport(3)
	r.Tabs = append(r.Tabs, Tab{ID: TabSockets, Name: "Sockets", Records: []Record{{Title: "alpha"}, {Title: "beta"}, {Title: "gamma"}}})
	b := sized(newBrowser(r), 160, 40)
	offers := func(b browser) bool { return strings.Contains(plain(b.helpView()), "(esc) clear search") }

	if b = keep(b, "check1"); len(b.visible) != 1 || !offers(b) {
		t.Fatalf("a kept search lists %d and offers esc %v", len(b.visible), offers(b))
	}
	if b = pressCode(b, tea.KeyEscape); b.query != "" || len(b.visible) != 3 || offers(b) {
		t.Errorf("esc on the list left %q, %d listed, esc offered %v", b.query, len(b.visible), offers(b))
	}

	b = keep(b, "check1")
	b.focus = focusFilters
	if b = pressCode(b, tea.KeyEscape); b.query != "" || len(b.visible) != 3 {
		t.Errorf("esc on the left pane left %q and %d listed", b.query, len(b.visible))
	}

	b.focus = focusList
	b = pressCode(keep(b, "check1"), tea.KeyEnter)
	if b.focus != focusDetail || offers(b) {
		t.Fatalf("in the detail pane, focus %d and esc offered %v", b.focus, offers(b))
	}
	if b = pressCode(b, tea.KeyEscape); b.focus != focusList || b.query != "check1" {
		t.Errorf("the first esc in the detail pane gave focus %d and search %q", b.focus, b.query)
	}
	if b = pressCode(b, tea.KeyEscape); b.query != "" || len(b.visible) != 3 {
		t.Errorf("the second esc left %q and %d listed", b.query, len(b.visible))
	}

	b = keep(press(b, "l"), "beta")
	if p := b.activePane(); len(p.visible) != 1 || !offers(b) {
		t.Fatalf("a kept search on the sockets tab lists %d and offers esc %v", len(p.visible), offers(b))
	}
	if b = pressCode(b, tea.KeyEscape); b.query != "" || len(b.activePane().visible) != 3 {
		t.Errorf("esc on the sockets tab left %q and %d listed", b.query, len(b.activePane().visible))
	}
}

// A finding with more evidence than the detail pane loads says under the
// evidence heading how much is shown and what x shows instead. Each press of x
// switches between the two, moves the pane to the heading so the change is in
// view, and changes the notice and the footer's hint.
func TestEvidenceToggleShowsWhatChanged(t *testing.T) {
	const extra = 3
	total := evidencePreview + extra
	r := sidebarReport(0)
	item := Item{Check: "permissions", Key: "permissions.world_writable_file", Result: "fail", Severity: "HIGH", Title: "a finding"}
	for i := 0; i < total; i++ {
		item.Evidence = append(item.Evidence, fmt.Sprintf("- /tmp/file%d", i))
	}
	r.Items = []Item{item}
	last := fmt.Sprintf("- /tmp/file%d", total-1)
	preview := fmt.Sprintf("showing the first %d; press x to show all %d", evidencePreview, total)
	all := fmt.Sprintf("showing all %d; press x to show the first %d", total, evidencePreview)

	// The window is wide enough for the footer to keep the findings' toggles,
	// which a narrow one drops first.
	b := sized(newBrowser(r), 240, 40)
	state := func(b browser) (content, top, footer string) {
		text, _ := b.detailText(item)
		view := strings.Split(plain(b.detail.View()), "\n")
		return plain(text), strings.TrimSpace(view[0]) + "\n" + strings.TrimSpace(view[1]), plain(b.helpView())
	}

	content, _, footer := state(b)
	if !strings.Contains(content, preview) || strings.Contains(content, last) || !strings.Contains(footer, "(x) all evidence") {
		t.Fatalf("before x: notice %v, last line %v, footer %q", strings.Contains(content, preview), strings.Contains(content, last), footer)
	}

	b = press(b, "x")
	content, top, footer := state(b)
	if !strings.Contains(content, all) || !strings.Contains(content, last) || !strings.Contains(footer, "(x) less evidence") {
		t.Errorf("after x: notice %v, last line %v, footer %q", strings.Contains(content, all), strings.Contains(content, last), footer)
	}
	if want := fmt.Sprintf("evidence (%d)\n%s", total, all); top != want {
		t.Errorf("after x the pane begins %q, want %q", top, want)
	}

	b = press(b, "x")
	content, top, footer = state(b)
	if !strings.Contains(content, preview) || strings.Contains(content, last) || !strings.Contains(footer, "(x) all evidence") {
		t.Errorf("after a second x: notice %v, last line %v, footer %q", strings.Contains(content, preview), strings.Contains(content, last), footer)
	}
	if want := fmt.Sprintf("evidence (%d)\n%s", total, preview); top != want {
		t.Errorf("after a second x the pane begins %q, want %q", top, want)
	}
}

// On a finding with no more evidence than the preview, x changes nothing and
// the footer does not offer it.
func TestEvidenceToggleNeedsMoreThanThePreview(t *testing.T) {
	r := sidebarReport(0)
	item := Item{Check: "permissions", Key: "permissions.world_writable_file", Result: "fail", Severity: "HIGH", Title: "a finding",
		Evidence: []string{"- /tmp/a", "- /tmp/b"}}
	r.Items = []Item{item}
	b := sized(newBrowser(r), 120, 40)
	before, _ := b.detailText(item)
	b = press(b, "x")
	after, _ := b.detailText(item)
	if b.fullEvidence || after != before || strings.Contains(plain(b.helpView()), "(x)") {
		t.Errorf("x on two lines of evidence: full %v, changed %v, footer %q", b.fullEvidence, after != before, plain(b.helpView()))
	}
}
