// internal/tui/theme.go

package tui

import (
	"image/color"

	"charm.land/lipgloss/v2"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// The palette every owatch terminal view draws from, so the live progress
// display and the results browser read as one program.
var (
	colorAccent   = lipgloss.Color("#7ee787")
	colorDone     = lipgloss.Color("#238636")
	colorRunning  = lipgloss.Color("#1f6feb")
	colorMuted    = lipgloss.Color("#8b949e")
	colorText     = lipgloss.Color("#e6edf3")
	colorCaution  = lipgloss.Color("#d29922")
	colorWarning  = lipgloss.Color("#f0883e")
	colorCritical = lipgloss.Color("#f85149")
	colorBrand    = lipgloss.Color("#79c0ff")

	// The brand in the browser's banner: the project, the tool's name and the
	// command that runs it.
	styleProject = lipgloss.NewStyle().Foreground(colorCritical).Bold(true)
	styleProduct = lipgloss.NewStyle().Foreground(colorBrand).Bold(true)
	styleCommand = lipgloss.NewStyle().Foreground(colorCaution)

	styleTitle  = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	styleMuted  = lipgloss.NewStyle().Foreground(colorMuted)
	styleText   = lipgloss.NewStyle().Foreground(colorText)
	styleNotice = lipgloss.NewStyle().Foreground(colorWarning).Bold(true)

	// styleSelected marks the row the keyboard is on.
	styleSelected = lipgloss.NewStyle().Reverse(true)
)

// severityColor returns the colour a severity is shown in. An unrecognised
// severity is shown muted rather than dressed up as one it is not.
func severityColor(severity string) color.Color {
	switch severity {
	case finding.SeverityCritical:
		return colorCritical
	case finding.SeverityHigh:
		return colorWarning
	case finding.SeverityMedium:
		return colorCaution
	default:
		return colorMuted
	}
}

// resultColor returns the colour a finished task's result is shown in when it
// produced no findings to take a colour from.
func resultColor(result finding.Result) color.Color {
	switch result {
	case finding.ResultPass:
		return colorAccent
	case finding.ResultFail:
		return colorWarning
	case finding.ResultError, finding.ResultUnknown:
		return colorCritical
	default:
		return colorMuted
	}
}

// itemColor returns the colour a browser item is shown in: its severity when
// it is a finding, its result otherwise.
func itemColor(item Item) color.Color {
	if item.isFinding() {
		return severityColor(item.Severity)
	}
	return resultColor(item.Result)
}
