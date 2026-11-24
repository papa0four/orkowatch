// internal/tui/filters_test.go

package tui

import (
	"slices"
	"strings"
	"testing"
)

// filteredReport has a record tab whose records fall under one status each,
// opening on the first status, and a second tab to leave it for.
func filteredReport() Report {
	record := func(title, status string) Record {
		return Record{Title: title, Subtitle: status, Filters: []string{status}}
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

// A tab with no filters shows that the left pane has none for it, as before.
func TestRecordTabWithoutFilters(t *testing.T) {
	b := sized(newBrowser(filteredReport()), 120, 40)
	b = press(b, "2")
	if frame := plain(b.View().Content); !strings.Contains(frame, "n/a") {
		t.Errorf("a tab with no filters shows none:\n%s", frame)
	}
}
