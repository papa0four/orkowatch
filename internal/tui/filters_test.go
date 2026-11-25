// internal/tui/filters_test.go

package tui

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// filteredReport has a record tab whose records fall under one status each,
// opening on the first status, and a second tab to leave it for.
func filteredReport() Report {
	record := func(title, status string) Record {
		return Record{Title: title, Subtitle: status, Filters: [][]string{{status}}}
	}
	return Report{
		Title: "owatch software",
		Tabs: []Tab{
			{ID: TabSockets, Name: "Matches", Noun: "matches",
				Filters: []Filter{{Name: "status", Options: []string{All, "fix available", "unfixed"}, Start: "fix available"}},
				Records: []Record{record("alpha", "fix available"), record("bravo", "unfixed"), record("charlie", "unfixed"), record("delta", "fix available")}},
			{ID: TabSystem, Name: "System", Note: "system note"},
		},
	}
}

// visibleTitles lists the titles the active pane shows.
func visibleTitles(b browser) []string {
	p := b.activePane()
	var titles []string
	for _, i := range p.visible {
		titles = append(titles, p.tab.Records[i].Title)
	}
	return titles
}

// apply chooses option of the active tab's filters, counting from the first
// option of the first filter.
func apply(b browser, option int) browser {
	b.focus = focusFilters
	b.filterCursor = len(b.tabs) + option
	b.onFilterKey("enter")
	return b
}

// A record tab opens on its filter's starting option; the left pane shows
// each option with how many of the whole tab's records fall under it;
// choosing another narrows the list to it; a search narrows within the
// filter; and the tab keeps its choice while another tab is shown.
func TestRecordTabFilters(t *testing.T) {
	b := sized(newBrowser(filteredReport()), 120, 40)
	if got := strings.Join(visibleTitles(b), ","); got != "alpha,delta" {
		t.Fatalf("the tab opened on %q, want the records with a fix available", got)
	}
	frame := plain(b.View().Content)
	for _, want := range []string{"matches: 2 of 4", "fix available", "unfixed", "all"} {
		if !strings.Contains(frame, want) {
			t.Errorf("the frame lacks %q:\n%s", want, frame)
		}
	}
	lines, _ := b.sidebarLines()
	counts := map[string]string{"fix available": "2", "unfixed": "2", "all": "4"}
	for option, count := range counts {
		found := false
		for _, line := range lines {
			fields := strings.Fields(plain(line))
			if len(fields) > 0 && strings.HasSuffix(strings.Join(fields, " "), option+" "+count) {
				found = true
			}
		}
		if !found {
			t.Errorf("the left pane does not count %s as %s:\n%s", option, count, strings.Join(lines, "\n"))
		}
	}

	b = apply(b, 2)
	if got := strings.Join(visibleTitles(b), ","); got != "bravo,charlie" {
		t.Errorf("unfixed shows %q", got)
	}
	b.focus = focusList
	b = keep(b, "char")
	if got := strings.Join(visibleTitles(b), ","); got != "charlie" {
		t.Errorf("a search within unfixed shows %q", got)
	}

	b = press(b, "2")
	b = press(b, "1")
	if got := strings.Join(visibleTitles(b), ","); got != "charlie" || b.activePane().groups[0].chosen != 2 {
		t.Errorf("back on the tab it shows %q with option %d chosen", got, b.activePane().groups[0].chosen)
	}

	// All, with the kept search cleared, shows every record.
	b = apply(b, 0)
	b.focus = focusList
	b = pressCode(b, 0x1b)
	if got := strings.Join(visibleTitles(b), ","); got != "alpha,bravo,charlie,delta" {
		t.Errorf("all shows %q", got)
	}
}

// The Findings tab's severity and check filters narrow its list as they did
// before every tab could have filters: a severity shows the findings of that
// severity, a check the rules of that check.
func TestFindingsFilters(t *testing.T) {
	report := Report{Title: "owatch audit", Items: []Item{
		{Check: "ssh", Key: "ssh.a", Result: "fail", Severity: "HIGH", Title: "a"},
		{Check: "ssh", Key: "ssh.b", Result: "fail", Severity: "LOW", Title: "b"},
		{Check: "users", Key: "users.c", Result: "fail", Severity: "HIGH", Title: "c"},
	}}
	b := sized(newBrowser(report), 120, 40)
	keys := func(b browser) string {
		var out []string
		for _, i := range b.visible {
			out = append(out, b.report.Items[i].Key)
		}
		return strings.Join(out, ",")
	}
	if got := keys(b); got != "ssh.a,ssh.b,users.c" {
		t.Fatalf("the findings open on %q", got)
	}
	high := 1 + slices.Index(b.findings[0].options[1:], "HIGH")
	b = apply(b, high)
	if got := keys(b); got != "ssh.a,users.c" {
		t.Errorf("severity high shows %q", got)
	}
	b = apply(b, 0)
	b = apply(b, len(b.findings[0].options)+2)
	if got := keys(b); got != "users.c" || !strings.Contains(plain(b.searchView()), "check users") {
		t.Errorf("check users shows %q, status %q", got, plain(b.searchView()))
	}
}

// Choosing a filter hands the keyboard to the list it narrowed, and esc from
// the list goes back to the left pane, to the filter last applied. With a
// search kept, the first esc clears it and the second goes back. Choosing a
// source keeps the keyboard in the left pane, so the next is one key away.
func TestFilterFocus(t *testing.T) {
	b := sized(newBrowser(filteredReport()), 120, 40)
	b = apply(b, 2)
	if b.focus != focusList {
		t.Fatalf("after a filter was chosen the keyboard is on pane %d, want the list", b.focus)
	}
	if hints := plain(b.View().Content); !strings.Contains(hints, "left pane") {
		t.Errorf("the list's hints do not say esc goes to the left pane:\n%s", hints)
	}
	b = pressCode(b, 0x1b)
	if b.focus != focusFilters || b.filterCursor != len(b.tabs)+2 {
		t.Errorf("esc left the keyboard on pane %d at row %d, want the left pane on the filter applied", b.focus, b.filterCursor)
	}

	b = apply(b, 1)
	b = keep(b, "alp")
	if hints := plain(b.View().Content); !strings.Contains(hints, "clear search") || strings.Contains(hints, "left pane") {
		t.Errorf("with a search kept the hints should offer esc to clear it, not to leave:\n%s", hints)
	}
	b = pressCode(b, 0x1b)
	if b.focus != focusList || b.query != "" {
		t.Errorf("the first esc with a search kept left pane %d and search %q, want the search cleared on the list", b.focus, b.query)
	}
	if b = pressCode(b, 0x1b); b.focus != focusFilters {
		t.Errorf("the second esc left the keyboard on pane %d", b.focus)
	}

	b.filterCursor = 1
	b.onFilterKey("enter")
	if b.focus != focusFilters || b.tabs[b.active].id != TabSystem {
		t.Errorf("choosing a source left pane %d on %q, want the left pane on System", b.focus, b.tabs[b.active].id)
	}

	// Enter on the source already open goes into its list.
	b.filterCursor = 0
	b.onFilterKey("enter")
	b.onFilterKey("enter")
	if b.focus != focusList || b.active != 0 {
		t.Errorf("enter on the open source left pane %d on tab %d, want its list", b.focus, b.active)
	}
}

// v opens the Vulnerabilities tab.
func TestVulnerabilitiesKey(t *testing.T) {
	report := filteredReport()
	report.Tabs[0].ID = TabVulnerabilities
	b := press(sized(newBrowser(report), 120, 40), "2")
	if b = press(b, "v"); b.tabs[b.active].id != TabVulnerabilities {
		t.Errorf("v opened %q", b.tabs[b.active].id)
	}
}

// A tab with no filters shows that the left pane has none for it, as before.
func TestRecordTabWithoutFilters(t *testing.T) {
	b := sized(newBrowser(filteredReport()), 120, 40)
	b = press(b, "2")
	if frame := plain(b.View().Content); !strings.Contains(frame, "n/a") {
		t.Errorf("a tab with no filters shows none:\n%s", frame)
	}
}

// A record can fall under several options of a filter, and a tab's switch
// key moves that filter between its two options from the list: to the second
// from the first, and back to the first from any other. The hints name it.
func TestFilterSwitch(t *testing.T) {
	record := func(title string, options ...string) Record {
		return Record{Title: title, Filters: [][]string{options}}
	}
	report := Report{Title: "owatch software", Tabs: []Tab{
		{ID: TabSoftware, Name: "Software",
			Filters: []Filter{{Name: "vulnerabilities", Options: []string{All, "affected", "fix available"}, Start: All}},
			Switch:  Switch{Key: "a", Filter: "vulnerabilities", A: All, B: "affected", Hint: "affected or all"},
			Records: []Record{record("clean"), record("both", "affected", "fix available"), record("unfixed", "affected")}},
		{ID: TabSystem, Name: "System", Note: "system note"},
	}}
	b := sized(newBrowser(report), 200, 40)
	if got := strings.Join(visibleTitles(b), ","); got != "clean,both,unfixed" {
		t.Fatalf("the tab opened on %q", got)
	}
	if hints := plain(b.View().Content); !strings.Contains(hints, "affected or all") {
		t.Errorf("the hints do not name the switch:\n%s", hints)
	}
	b = press(b, "a")
	if got := strings.Join(visibleTitles(b), ","); got != "both,unfixed" {
		t.Errorf("a shows %q, want the affected", got)
	}
	b = apply(b, 2)
	if got := strings.Join(visibleTitles(b), ","); got != "both" {
		t.Errorf("fix available shows %q", got)
	}
	b = press(b, "a")
	if got := strings.Join(visibleTitles(b), ","); got != "clean,both,unfixed" {
		t.Errorf("a from fix available shows %q, want all", got)
	}
	lines, _ := b.sidebarLines()
	if joined := plain(strings.Join(lines, "\n")); !strings.Contains(joined, "affected") || !regexp.MustCompile(`affected\s+2`).MatchString(joined) || !regexp.MustCompile(`fix available\s+1`).MatchString(joined) {
		t.Errorf("the counts are wrong:\n%s", joined)
	}
}
