// internal/tui/browser_test.go

package tui

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
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
		for _, want := range []string{"f Findings", "o System", "s Software", "summary"} {
			if !strings.Contains(frame, want) {
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
