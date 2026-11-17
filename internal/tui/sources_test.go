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

// A rule under the banner separates it from the panes, and where the left pane
// is shown it joins the rule between that pane and the main one, so the banner
// is never read as part of the sources table.
func TestHeaderRuleSeparatesBanner(t *testing.T) {
	lines := strings.Split(plain(sized(newBrowser(sidebarReport(1)), 120, 30).render()), "\n")
	if !strings.HasPrefix(lines[0], "all") {
		t.Fatalf("the first line is not the banner: %q", lines[0])
	}
	rule := []rune(lines[1])
	if len(rule) < filterWidth+1 || rule[filterWidth] != '┬' || strings.Trim(lines[1], "─┬") != "" {
		t.Errorf("the line under the banner is not a rule joined to the pane divider: %q", lines[1])
	}
	if !strings.Contains(lines[2], "key") || !strings.Contains(lines[2], "source") {
		t.Errorf("the sources headings do not follow the rule: %q", lines[2])
	}

	narrow := strings.Split(plain(sized(newBrowser(sidebarReport(1)), 40, 20).render()), "\n")
	if strings.Trim(narrow[1], "─") != "" {
		t.Errorf("a window with no left pane has no plain rule under the banner: %q", narrow[1])
	}
}

// The banner names the run, the host and a readable time on the left, without
// the tool's name, which the brand on the right carries; a window too narrow
// for both keeps the left.
func TestBannerPutsTheBrandOnTheRight(t *testing.T) {
	r := sidebarReport(1)
	r.Host, r.When = "defender", "2026-11-17T03:03:32Z"
	banner := strings.Split(plain(sized(newBrowser(r), 120, 30).render()), "\n")[0]
	if !strings.HasPrefix(banner, "all · defender · 2026-11-17 03:03:32 UTC") {
		t.Errorf("the left of the banner: %q", banner)
	}
	if !strings.HasSuffix(banner, "Project Orko  Orko Watch (owatch)") || strings.Count(banner, "owatch") != 1 {
		t.Errorf("the right of the banner: %q", banner)
	}
	if width := len([]rune(banner)); width != 120 {
		t.Errorf("the banner is %d columns in a 120-column window", width)
	}

	narrow := strings.Split(plain(sized(newBrowser(r), 50, 20).render()), "\n")[0]
	if strings.Contains(narrow, "Project Orko") || !strings.HasPrefix(narrow, "all · defender") {
		t.Errorf("a narrow banner: %q", narrow)
	}
}

// A rule closes the table of sources and joins the divider beside it, on
// every source.
func TestSourcesRuleJoinsTheDivider(t *testing.T) {
	b := sized(newBrowser(sidebarReport(1)), 120, 30)
	for _, key := range []string{"f", "s"} {
		b = press(b, key)
		lines := strings.Split(plain(b.render()), "\n")
		row := []rune(lines[2+1+len(b.tabs)])
		if len(row) <= filterWidth || row[filterWidth] != '┤' || strings.Trim(string(row[:filterWidth]), "─") != "" {
			t.Errorf("after %q the line under the sources is not a rule joined to the divider: %q", key, string(row))
		}
	}
}
