// internal/tui/model.go

package tui

import (
	"context"
	"fmt"
	"image/color"
	"strings"
	"time"

	"charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

const (
	// Display widths. The display follows the terminal between these.
	minWidth     = 40
	maxWidth     = 100
	defaultWidth = 80

	// labelWidth is the column the task labels are padded to.
	labelWidth = 28

	// markerWidth is the column the state markers are padded to: the three
	// cells of a result symbol and one of space.
	markerWidth = 4

	// interruptKey is the key press that stops the work.
	interruptKey = "ctrl+c"

	// The display asks the terminal two questions as it starts, and the
	// terminal answers by typing into the program's input. A run that ends
	// before the answers arrive would leave them for the shell to print as
	// stray text, so the display stays up until both are in. Not every
	// terminal answers, so the wait is bounded: settleLimit is the longest a
	// finished run is held, measured from when the display started, which
	// only a run shorter than that ever notices.
	terminalReplies = 2
	settleLimit     = 400 * time.Millisecond

	// feedLimit is how many of the most recent findings the feed keeps on
	// screen; the full set is in the report that follows.
	feedLimit = 10
)

// taskStatus is where a task is in its life.
type taskStatus uint8

const (
	taskPending taskStatus = iota
	taskRunning
	taskFinished
	taskSkipped
)

type (
	// taskRow is one task and what the display knows about it.
	taskRow struct {
		Task
		status  taskStatus
		started time.Time
		took    time.Duration
		outcome Outcome
	}

	// feedLine is one finding in the live feed, with the task it came from.
	feedLine struct {
		task string
		Finding
	}

	// model is the display's state. It is only ever touched by the Bubble
	// Tea event loop, which is what lets the reports from concurrent work
	// arrive as messages and need no lock.
	model struct {
		title       string
		rows        []taskRow
		index       map[string]int
		feed        []feedLine
		verbose     bool
		width       int
		started     time.Time
		spinner     spinner.Model
		bar         progress.Model
		cancel      context.CancelFunc
		interrupted bool
		done        bool
		replies     int
	}

	taskStartedMsg struct {
		id string
	}

	taskFinishedMsg struct {
		id      string
		outcome Outcome
	}

	workDoneMsg struct{}

	// settledMsg says the wait for the terminal's replies has run out.
	settledMsg struct{}
)

func newModel(opts Options, cancel context.CancelFunc) model {
	m := model{
		title:   opts.Title,
		index:   make(map[string]int, len(opts.Tasks)),
		verbose: opts.Verbose,
		width:   defaultWidth,
		started: time.Now(),
		spinner: spinner.New(spinner.WithSpinner(spinner.MiniDot), spinner.WithStyle(lipgloss.NewStyle().Foreground(colorRunning))),
		bar:     progress.New(progress.WithColors(colorDone), progress.WithoutPercentage()),
		cancel:  cancel,
	}
	for i, task := range opts.Tasks {
		row := taskRow{Task: task}
		if task.Skipped {
			row.status = taskSkipped
		}
		m.rows = append(m.rows, row)
		m.index[task.ID] = i
	}
	return m
}

func (m model) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		// The first interrupt asks the work to stop and keeps the display
		// up until it has, so what finished is still shown and reported.
		if msg.String() == interruptKey && !m.interrupted {
			m.interrupted = true
			m.cancel()
		}
		return m, nil

	case tea.WindowSizeMsg:
		m.width = min(max(msg.Width, minWidth), maxWidth)
		return m, nil

	case taskStartedMsg:
		if i, ok := m.index[msg.id]; ok {
			m.rows[i].status = taskRunning
			m.rows[i].started = time.Now()
		}
		return m, nil

	case taskFinishedMsg:
		if i, ok := m.index[msg.id]; ok {
			row := &m.rows[i]
			row.status = taskFinished
			row.outcome = msg.outcome
			if !row.started.IsZero() {
				row.took = time.Since(row.started)
			}
			for _, found := range msg.outcome.Findings {
				m.feed = append(m.feed, feedLine{task: row.Label, Finding: found})
			}
		}
		return m, nil

	case workDoneMsg:
		m.done = true
		if m.settled() {
			return m, tea.Quit
		}
		return m, tea.Tick(time.Until(m.started.Add(settleLimit)), func(time.Time) tea.Msg { return settledMsg{} })

	case tea.ModeReportMsg:
		m.replies++
		if m.done && m.settled() {
			return m, tea.Quit
		}
		return m, nil

	case settledMsg:
		return m, tea.Quit

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m model) View() tea.View {
	return tea.NewView(m.render())
}

// render draws the whole display as text.
func (m model) render() string {
	var b strings.Builder

	elapsed := styleMuted.Render(clock(time.Since(m.started)))
	title := styleTitle.Render(m.title)
	gap := max(m.width-lipgloss.Width(title)-lipgloss.Width(elapsed), 1)
	b.WriteString(title + strings.Repeat(" ", gap) + elapsed + "\n\n")

	finished, total := m.progress()
	m.bar.SetWidth(m.width)
	b.WriteString(styleMuted.Render(fmt.Sprintf("%d of %d complete", finished, total)) + "\n")
	b.WriteString(m.bar.ViewAs(fraction(finished, total)) + "\n\n")

	for _, row := range m.rows {
		b.WriteString(m.rowView(row) + "\n")
	}

	if m.verbose {
		b.WriteString("\n" + styleMuted.Render("live findings") + "\n")
		b.WriteString(m.feedView())
	}

	switch {
	case m.done:
	case m.interrupted:
		b.WriteString("\n" + styleNotice.Render("stopping; waiting for running checks to return") + "\n")
	default:
		b.WriteString("\n" + styleMuted.Render("scan in progress") + "  " + styleNotice.Render("press ctrl+c to abort") + "\n")
	}
	return b.String()
}

// settled reports whether the terminal has answered everything the display
// asked it, or has had as long as it is going to get.
func (m model) settled() bool {
	return m.replies >= terminalReplies || time.Since(m.started) >= settleLimit
}

// progress counts the tasks that will run and how many of them have.
func (m model) progress() (finished, total int) {
	for _, row := range m.rows {
		switch row.status {
		case taskSkipped:
		case taskFinished:
			finished++
			total++
		default:
			total++
		}
	}
	return finished, total
}

// rowView renders one task: a marker for its state in a fixed column, its
// label, and what is known about it so far.
func (m model) rowView(row taskRow) string {
	label := fmt.Sprintf("%-*s", labelWidth, row.Label)

	switch row.status {
	case taskRunning:
		return marker(m.spinner.View()) + styleText.Render(label) + styleMuted.Render("running "+clock(time.Since(row.started)))
	case taskSkipped:
		return styleMuted.Render(marker("-") + label + "not selected")
	case taskFinished:
		tint, summary := outcomeSummary(row.outcome)
		style := lipgloss.NewStyle().Foreground(tint)
		line := style.Render(marker(resultMark(row.outcome.Result))+label) + styleMuted.Render(summary+"  "+clock(row.took))
		if row.outcome.Reason != "" && len(row.outcome.Findings) == 0 {
			line += "\n" + styleMuted.Render(truncate(marker("")+row.outcome.Reason, m.width))
		}
		return line
	default:
		return styleMuted.Render(marker("") + label + "waiting")
	}
}

// marker pads a row's state marker to the width of the widest one, so the
// labels beside it line up whatever state each row is in.
func marker(mark string) string {
	return mark + strings.Repeat(" ", max(markerWidth-lipgloss.Width(mark), 1))
}

// feedView renders the most recent findings, or a placeholder so the block
// keeps its place before any arrive.
func (m model) feedView() string {
	if len(m.feed) == 0 {
		return styleMuted.Render("  none yet") + "\n"
	}

	var b strings.Builder
	lines := m.feed
	if len(lines) > feedLimit {
		b.WriteString(styleMuted.Render(fmt.Sprintf("  %d earlier", len(lines)-feedLimit)) + "\n")
		lines = lines[len(lines)-feedLimit:]
	}
	for _, line := range lines {
		symbol, severity := finding.SeverityFormat(line.Severity)
		style := lipgloss.NewStyle().Foreground(severityColor(line.Severity))
		text := fmt.Sprintf("  %s %s  %s", symbol, severity, line.Title)
		b.WriteString(style.Render(truncate(text, m.width)) + "\n")
	}
	return b.String()
}

// outcomeSummary returns the colour and the words for a finished task: its
// findings when it has any, coloured by the worst of them, and its result
// otherwise.
func outcomeSummary(outcome Outcome) (color.Color, string) {
	if count := len(outcome.Findings); count > 0 {
		worst := outcome.Findings[0].Severity
		for _, found := range outcome.Findings[1:] {
			if finding.SeverityLevel(found.Severity) > finding.SeverityLevel(worst) {
				worst = found.Severity
			}
		}
		noun := "findings"
		if count == 1 {
			noun = "finding"
		}
		return severityColor(worst), fmt.Sprintf("%d %s", count, noun)
	}
	return resultColor(outcome.Result), string(outcome.Result)
}

// resultMark returns the report symbol for a result, so a row in the display
// carries the same mark the text report uses.
func resultMark(result finding.Result) string {
	switch result {
	case finding.ResultPass:
		return finding.SymbolOK
	case finding.ResultFail:
		return finding.SymbolWarning
	case finding.ResultError, finding.ResultUnknown:
		return finding.SymbolError
	default:
		return finding.SymbolInfo
	}
}

// fraction returns part of whole as the progress bar wants it, treating a
// run with nothing to do as complete.
func fraction(part, whole int) float64 {
	if whole == 0 {
		return 1
	}
	return float64(part) / float64(whole)
}

// clock renders a duration as minutes and seconds.
func clock(d time.Duration) string {
	seconds := int(d.Seconds())
	return fmt.Sprintf("%02d:%02d", seconds/60, seconds%60)
}

// truncate shortens text to width display cells so a long title cannot wrap
// and break the layout.
func truncate(text string, width int) string {
	if lipgloss.Width(text) <= width {
		return text
	}
	runes := []rune(text)
	for len(runes) > 0 && lipgloss.Width(string(runes))+1 > width {
		runes = runes[:len(runes)-1]
	}
	return string(runes) + "…"
}
