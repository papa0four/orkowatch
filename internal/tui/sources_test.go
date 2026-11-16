// internal/tui/sources_test.go

package tui

import (
	"strings"
	"testing"
)

// The sources are a table under the headings key and source, one row each, the
// names starting in one column, and a source with no key listed with the key
// column blank.
func TestSourcesAreAColumn(t *testing.T) {
	r := sidebarReport(1)
	r.Tabs = append(r.Tabs, Tab{ID: TabAttack, Name: "MITRE ATT&CK", Note: "n"}, Tab{ID: "other", Name: "Unkeyed", Note: "n"})
	frame := plain(sized(newBrowser(r), 120, 30).render())

	var heading string
	names := map[string]int{}
	for _, line := range strings.Split(frame, "\n") {
		left, _, _ := strings.Cut(line, "\u2502")
		if strings.Contains(left, "key") && strings.Contains(left, "source") {
			heading = left
			continue
		}
		for _, name := range []string{"Findings", "System", "Software", "MITRE ATT&CK", "Unkeyed"} {
			if col := strings.Index(left, name); col >= 0 {
				names[name] = col
			}
		}
	}
	if heading == "" {
		t.Fatalf("the left pane has no key and source headings:\n%s", frame)
	}
	column := strings.Index(heading, "source")
	if len(names) != 5 {
		t.Fatalf("not every source is listed: %v\n%s", names, frame)
	}
	for name, col := range names {
		if col != column {
			t.Errorf("%s starts in column %d, under a heading at column %d:\n%s", name, col, column, frame)
		}
	}
}

// The footer states navigation and not the key of each source, which the left
// pane lists, so it does not grow with the sources.
func TestFooterDoesNotNameSourceKeys(t *testing.T) {
	r := sidebarReport(1)
	r.Tabs = append(r.Tabs, Tab{ID: TabAttack, Name: "MITRE ATT&CK", Note: "n"})
	footer := plain(sized(newBrowser(r), 140, 30).helpView())
	for _, want := range []string{"([ ]) prev/next source", "(tab) switch pane"} {
		if !strings.Contains(footer, want) {
			t.Errorf("the footer lacks %q:\n%s", want, footer)
		}
	}
	for _, key := range []string{"(f", "(o", "(s", "(m", "letter"} {
		if strings.Contains(footer, key) {
			t.Errorf("the footer names a source key %q:\n%s", key, footer)
		}
	}
}
