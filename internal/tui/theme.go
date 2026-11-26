// internal/tui/theme.go

package tui

import (
	"charm.land/lipgloss/v2"

	"github.com/papa0four/orkowatch/internal/tone"
)

// The colors of the terminal views' own frame, apart from the palette that
// states what a finding or a vulnerability means: headings, the brand, the
// spinner and the progress bar, muted and plain text, and a notice of what the
// operator has to do. None of them is a color of the palette, so nothing in the
// frame reads as a severity.
var (
	colorAccent  = lipgloss.Color("#7ee787")
	colorDone    = lipgloss.Color("#238636")
	colorRunning = lipgloss.Color("#1f6feb")
	colorMuted   = lipgloss.Color("#8b949e")
	colorText    = lipgloss.Color("#e6edf3")
	colorCommand = lipgloss.Color("#d29922")
	colorNotice  = lipgloss.Color("#f0883e")
	colorProject = lipgloss.Color("#f85149")
	colorBrand   = lipgloss.Color("#79c0ff")

	// The brand in the browser's banner: the project, the tool's name and the
	// command that runs it.
	styleProject = lipgloss.NewStyle().Foreground(colorProject).Bold(true)
	styleProduct = lipgloss.NewStyle().Foreground(colorBrand).Bold(true)
	styleCommand = lipgloss.NewStyle().Foreground(colorCommand)

	styleTitle  = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	styleMuted  = lipgloss.NewStyle().Foreground(colorMuted)
	styleText   = lipgloss.NewStyle().Foreground(colorText)
	styleNotice = lipgloss.NewStyle().Foreground(colorNotice).Bold(true)

	// styleSelected marks the row the keyboard is on.
	styleSelected = lipgloss.NewStyle().Reverse(true)
)

// itemTone is the tone of a browser item's word: its severity when it is a
// finding, its result otherwise.
func itemTone(item Item) tone.Tone {
	if item.isFinding() {
		return tone.ForSeverity(item.Severity)
	}
	return tone.ForResult(item.Result)
}
