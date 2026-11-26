// internal/tone/tone.go

// Package tone is the one palette owatch colors its terminal views with: the
// results browser and the live progress display. Severity, exploitation, and
// execution are three things about a finding or a vulnerability, and each is
// colored by its own meaning, with no color standing for two. Reports are
// never colored, since other tools read them, so nothing that writes a report
// uses this package.
package tone

import (
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// Tone is what a word means, as its color says it.
type Tone int

// The tones. Plain is text that carries no meaning a color should state, drawn
// in the terminal's own color.
const (
	Plain Tone = iota
	KnownExploited
	Critical
	High
	Medium
	Low
	Negligible
	None
	Error
)

// colors are the tones' colors, the 256-color palette's own values, so a
// terminal of 256 colors shows each as itself: known exploited 197, critical
// 196, high 208, medium 220, low 81, negligible 244, none 77, error 207.
var colors = map[Tone]color.Color{
	KnownExploited: lipgloss.Color("#FF005F"),
	Critical:       lipgloss.Color("#FF0000"),
	High:           lipgloss.Color("#FF8700"),
	Medium:         lipgloss.Color("#FFD700"),
	Low:            lipgloss.Color("#5FD7FF"),
	Negligible:     lipgloss.Color("#808080"),
	None:           lipgloss.Color("#5FD75F"),
	Error:          lipgloss.Color("#FF5FFF"),
}

// bold are the tones that need the operator now: confirmed exploitation, a
// critical severity, and a check that could not run.
var bold = map[Tone]bool{KnownExploited: true, Critical: true, Error: true}

// severities places the words of both severity scales owatch reads, a
// finding's and a vulnerability's, compared without case. A vulnerability
// whose records state no severity, and a word owatch does not know, are not
// here: an unstated severity is unknown, not clean.
var severities = map[string]Tone{
	"critical":   Critical,
	"high":       High,
	"medium":     Medium,
	"low":        Low,
	"negligible": Negligible,
	"none":       None,
}

// ForSeverity is the tone of a severity, on either scale.
func ForSeverity(name string) Tone {
	return severities[strings.ToLower(name)]
}

// ForResult is the tone of a check's result: a pass is clean, a check that
// could not run or whose outcome could not be read is an error, and a failure
// takes its tone from the severity of what it found.
func ForResult(r finding.Result) Tone {
	switch r {
	case finding.ResultPass:
		return None
	case finding.ResultError, finding.ResultUnknown:
		return Error
	default:
		return Plain
	}
}

// Color is the tone's color, or nil for Plain.
func (t Tone) Color() color.Color {
	return colors[t]
}

// Style is how text of the tone is drawn: in its color, bold when it needs the
// operator now, and untouched when it is Plain.
func (t Tone) Style() lipgloss.Style {
	style := lipgloss.NewStyle()
	if c := t.Color(); c != nil {
		style = style.Foreground(c)
	}
	return style.Bold(bold[t])
}

// Render draws text in the tone.
func (t Tone) Render(text string) string {
	if t == Plain {
		return text
	}
	return t.Style().Render(text)
}
