// internal/tui/tui.go

// Package tui draws owatch's terminal interface. Run shows a long scan's
// progress while it happens: which tasks are running, which have finished
// and with what result, the findings as they arrive, and the time elapsed.
// The work being shown knows nothing about the display; it reports through
// a Reporter and is otherwise unchanged, so the same work runs silently, or
// with plain progress lines, when there is no terminal to draw on.
package tui

import (
	"context"
	"errors"
	"fmt"
	"io"

	tea "charm.land/bubbletea/v2"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// ErrInterrupted is returned by Run when the operator stopped the work from
// the display. The work has returned by then, with whatever it finished.
var ErrInterrupted = errors.New("interrupted by operator")

type (
	// Task is one unit of work the display has a row for. Skipped marks a
	// task the operator excluded: it keeps its row, so the display accounts
	// for everything the run could have done.
	Task struct {
		ID      string
		Label   string
		Skipped bool
	}

	// Finding is one finding as the live feed shows it.
	Finding struct {
		Severity string
		Title    string
	}

	// Outcome is how a task ended. Reason is shown when Result is neither
	// pass nor fail.
	Outcome struct {
		Result   finding.Result
		Reason   string
		Findings []Finding
	}

	// Reporter is how running work tells the display what it is doing. The
	// methods may be called from several goroutines at once.
	Reporter interface {
		Start(id string)
		Finish(id string, outcome Outcome)
	}

	// Options configures a run. Interactive selects the live display, which
	// needs a terminal on standard output. Without it, Lines receives one
	// plain line per task as it starts, or nothing when Lines is nil.
	// Verbose adds the live findings feed to the display.
	Options struct {
		Title       string
		Tasks       []Task
		Interactive bool
		Verbose     bool
		Lines       io.Writer
	}

	// programReporter forwards reports to a running display.
	programReporter struct {
		program *tea.Program
	}

	// lineReporter writes the plain progress lines used without a terminal.
	lineReporter struct {
		w      io.Writer
		labels map[string]string
	}
)

// Run calls work and shows its progress until it returns. The context passed
// to work is cancelled when the operator interrupts from the display, in
// which case Run returns ErrInterrupted once work has returned, unless work
// itself failed. Otherwise Run returns work's error.
func Run(ctx context.Context, opts Options, work func(context.Context, Reporter) error) error {
	if !opts.Interactive {
		return work(ctx, newLineReporter(opts))
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	program := tea.NewProgram(newModel(opts, cancel))

	// The display ends when the work does: the work's goroutine sends the
	// message that makes the program quit, so by the time Run on the program
	// returns normally, workErr has been written and is safe to read.
	var workErr error
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		workErr = work(ctx, programReporter{program: program})
		program.Send(workDoneMsg{})
	}()

	final, err := program.Run()

	// Whatever ended the display, the work is stopped and waited for before
	// Run returns, so nothing is left running behind it. After a normal end
	// the work has already returned and cancelling it changes nothing.
	cancel()
	<-finished

	m, _ := final.(model)
	switch {
	case workErr != nil:
		return workErr
	case errors.Is(err, tea.ErrInterrupted), err == nil && m.interrupted:
		// An interrupt signal ends the display from outside; the key press
		// ends it from inside. Both mean the operator stopped the run.
		return ErrInterrupted
	case err != nil:
		return fmt.Errorf("progress display: %w", err)
	default:
		return nil
	}
}

func (r programReporter) Start(id string) {
	r.program.Send(taskStartedMsg{id: id})
}

func (r programReporter) Finish(id string, outcome Outcome) {
	r.program.Send(taskFinishedMsg{id: id, outcome: outcome})
}

// newLineReporter announces the skipped tasks at once, since nothing will
// ever start them, and returns the reporter that announces the rest.
func newLineReporter(opts Options) lineReporter {
	r := lineReporter{w: opts.Lines, labels: make(map[string]string, len(opts.Tasks))}
	for _, task := range opts.Tasks {
		r.labels[task.ID] = task.Label
		if task.Skipped && r.w != nil {
			_, _ = fmt.Fprintf(r.w, "[*] Skipping %s...\n", task.Label) //nolint:errcheck // progress line; a failed write must not fail the scan
		}
	}
	return r
}

func (r lineReporter) Start(id string) {
	if r.w != nil {
		_, _ = fmt.Fprintf(r.w, "[*] Running %s...\n", r.labels[id]) //nolint:errcheck // progress line; a failed write must not fail the scan
	}
}

func (lineReporter) Finish(string, Outcome) {}
