// internal/tui/theme_test.go

package tui

import (
	"fmt"
	"image/color"
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/tone"
)

// No color of the views' frame is a color of the palette, so nothing in the
// frame reads as a severity, an exploitation, or an error.
func TestFrameIsNotThePalette(t *testing.T) {
	frame := []color.Color{colorAccent, colorDone, colorRunning, colorMuted, colorText, colorCommand, colorNotice, colorProject, colorBrand}
	for tn := tone.KnownExploited; tn <= tone.Error; tn++ {
		for _, c := range frame {
			if fmt.Sprint(c.RGBA()) == fmt.Sprint(tn.Color().RGBA()) {
				t.Errorf("the frame uses tone %d's color", tn)
			}
		}
	}
}

// A finding's row colors only the word of its severity, and a rule that did
// not fail only the word of its result; the rest of the row is plain.
func TestRowColorsOnlyItsWord(t *testing.T) {
	b := newBrowser(Report{Title: "owatch audit", Items: []Item{
		{Check: "ssh", Key: "ssh.root", Result: "fail", Severity: "HIGH", Title: "root may log in"},
		{Check: "ssh", Key: "ssh.read", Result: "error", Reason: "not readable"},
	}})
	b.width, b.height = 160, 40
	b.focus = focusFilters
	lines := strings.Split(b.listView(), "\n")
	for i, want := range []struct {
		tn   tone.Tone
		word string
		rest string
	}{{tone.High, "high", "root may log in"}, {tone.Error, "error", "ssh.read"}} {
		line := lines[i]
		colored := want.tn.Render(fmt.Sprintf("%-*s", resultColumn, want.word))
		if !strings.Contains(line, colored) {
			t.Errorf("row %d %q does not color %q in its tone", i, line, want.word)
		}
		if after := line[strings.Index(line, colored)+len(colored):]; !strings.Contains(after, want.rest) || strings.Contains(after, "\x1b[") {
			t.Errorf("row %d colors more than its word: %q", i, line)
		}
	}
}

// The progress display's feed colors a finding's severity and its mark, and
// not its title.
func TestFeedColorsOnlyTheSeverity(t *testing.T) {
	m := model{width: 120, feed: []feedLine{{task: "ssh", Finding: Finding{Severity: "CRITICAL", Title: "root may log in"}}}}
	line := strings.TrimSuffix(m.feedView(), "\n")
	if !strings.HasSuffix(line, "  root may log in") || !strings.Contains(line, "\x1b[") {
		t.Errorf("the feed line is %q, want its severity colored and its title plain", line)
	}
	const reset = "\x1b[m"
	if at := strings.LastIndex(line, reset); at < 0 || line[at+len(reset):] != "  root may log in" {
		t.Errorf("the title is colored: %q", line)
	}
}

// A record's row colors only the words its subtitle tones, an alert band's row
// is whole in the known-exploited tone, and the selected row is plain.
func TestRecordRowTones(t *testing.T) {
	sub := Line{{Text: "fix 2  "}, {Text: "high", Tone: tone.High}}
	p := newRecordPane(Tab{ID: TabVulnerabilities, Name: "Vulnerabilities", Alert: "known", Records: []Record{
		{Title: "CVE-1", Subtitle: sub, Band: "known"},
		{Title: "CVE-2", Subtitle: sub, Band: "rest"},
		{Title: "CVE-3", Subtitle: sub, Band: "rest"},
	}})
	p.refilter("")
	p.cursor = 2
	p.show(10, 80)
	var rows []string
	for _, line := range strings.Split(p.listView(10, 80, true), "\n") {
		if text := plain(line); strings.HasPrefix(text, "CVE-") {
			rows = append(rows, line)
		}
	}
	if len(rows) != 3 {
		t.Fatalf("rows %q", rows)
	}
	if rows[0] != tone.KnownExploited.Style().Render("CVE-1  fix 2  high") {
		t.Errorf("the alert row is not whole in the known-exploited tone: %q", rows[0])
	}
	if !strings.Contains(rows[1], "CVE-2  fix 2  "+tone.High.Render("high")) {
		t.Errorf("the row does not color only its toned word: %q", rows[1])
	}
	if strings.Contains(rows[2], tone.High.Render("high")) {
		t.Errorf("the selected row keeps a tone: %q", rows[2])
	}
}
