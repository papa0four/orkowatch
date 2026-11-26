// internal/tui/refresh.go

package tui

import (
	"context"
	"errors"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

type (
	// Refresher fetches the datasets a report was matched against and
	// matches it again, for the browser's r. The command that built the
	// report supplies it; a report with none offers no r.
	Refresher interface {
		// Plan is what a refresh would fetch, a line for each dataset. A
		// Leave is a refresh that cannot be made here: the browser closes
		// and its text is for the command to print.
		Plan(ctx context.Context) ([]string, error)

		// Fetch fetches what Plan named, telling line each line of its
		// progress, and returns the report matched again.
		Fetch(ctx context.Context, line func(string)) (Report, error)
	}

	// Leave is a refresh the browser cannot make, such as one asked of an
	// elevated run, which never fetches. Text says what to run instead.
	Leave struct {
		Text string
	}

	// refreshPhase is where a refresh asked for with r stands.
	refreshPhase uint8

	// refreshState is the browser's refresh: its phase, what the plan named,
	// the last line of progress, why the last one failed, which is shown in
	// place of the results until the next key, a notice for the footer, such
	// as that the last one was canceled, the cancel of the one under way, and
	// its attempt, which a message of an attempt since canceled does not
	// match.
	refreshState struct {
		phase    refreshPhase
		plan     []string
		progress string
		failed   string
		notice   string
		cancel   context.CancelFunc
		attempt  int
	}

	// The messages of a refresh, each of the attempt that sent it.
	plannedMsg struct {
		attempt int
		plan    []string
		err     error
	}
	progressMsg struct {
		attempt int
		line    string
		events  <-chan tea.Msg
	}
	fetchedMsg struct {
		attempt int
		report  Report
		err     error
	}
)

const (
	refreshIdle refreshPhase = iota
	refreshSizing
	refreshAsking
	refreshFetching
)

// refreshQuestion is what the browser asks once the plan is shown.
const refreshQuestion = "Fetch these and match again? [y/N]"

func (l Leave) Error() string { return l.Text }

// startRefresh plans a refresh in the background, so sizing the datasets over
// the network does not hold the screen.
func (b *browser) startRefresh() tea.Cmd {
	ctx := b.beginAttempt(refreshSizing)
	refresh, attempt := b.report.Refresh, b.refreshing.attempt
	return func() tea.Msg {
		plan, err := refresh.Plan(ctx)
		return plannedMsg{attempt: attempt, plan: plan, err: err}
	}
}

// startFetch fetches what the plan named in the background, its progress
// arriving as messages until the report matched again does.
func (b *browser) startFetch() tea.Cmd {
	ctx := b.beginAttempt(refreshFetching)
	refresh, attempt := b.report.Refresh, b.refreshing.attempt
	events := make(chan tea.Msg)
	send := func(msg tea.Msg) {
		select {
		case events <- msg:
		case <-ctx.Done():
		}
	}
	go func() {
		report, err := refresh.Fetch(ctx, func(line string) {
			send(progressMsg{attempt: attempt, line: line, events: events})
		})
		// A canceled attempt still says how it ended, so a listener left
		// waiting on it is released.
		events <- fetchedMsg{attempt: attempt, report: report, err: err}
	}()
	return listen(events)
}

// listen is the next message of a fetch.
func listen(events <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg { return <-events }
}

// beginAttempt starts a new attempt in phase and returns the context it runs
// under.
func (b *browser) beginAttempt(phase refreshPhase) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	b.refreshing.attempt++
	b.refreshing.phase, b.refreshing.cancel = phase, cancel
	b.refreshing.progress, b.refreshing.failed, b.refreshing.notice = "", "", ""
	return ctx
}

// endAttempt leaves the refresh idle, with why the last one failed, if it
// did. The attempt is passed, so nothing it sends after, such as a report a
// canceled fetch finished anyway, is taken.
func (b *browser) endAttempt(failed string) {
	if b.refreshing.cancel != nil {
		b.refreshing.cancel()
	}
	b.refreshing.attempt++
	b.refreshing.phase, b.refreshing.cancel, b.refreshing.plan = refreshIdle, nil, nil
	b.refreshing.progress, b.refreshing.failed, b.refreshing.notice = "", failed, ""
}

// onRefreshMsg takes a refresh's message, unless it is of an attempt since
// canceled, reporting whether msg was one.
func (b browser) onRefreshMsg(msg tea.Msg) (tea.Model, tea.Cmd, bool) {
	switch msg := msg.(type) {
	case plannedMsg:
		if msg.attempt != b.refreshing.attempt {
			return b, nil, true
		}
		var leave Leave
		switch {
		case errors.As(msg.err, &leave):
			b.endAttempt("")
			b.leave = &leave
			return b, tea.Quit, true
		case msg.err != nil:
			b.endAttempt(msg.err.Error())
		default:
			b.refreshing.phase, b.refreshing.plan = refreshAsking, msg.plan
		}
		return b, nil, true

	case progressMsg:
		if msg.attempt == b.refreshing.attempt {
			b.refreshing.progress = msg.line
		}
		return b, listen(msg.events), true

	case fetchedMsg:
		if msg.attempt != b.refreshing.attempt {
			return b, nil, true
		}
		if msg.err != nil {
			b.endAttempt(msg.err.Error())
			return b, nil, true
		}
		return b.replacedBy(msg.report), nil, true
	}
	return b, nil, false
}

// onRefreshKey takes a key while a refresh is under way or asking, reporting
// whether it did. While sizing or fetching, esc cancels and q quits; asked,
// y fetches and anything else fetches nothing.
func (b browser) onRefreshKey(key string) (tea.Model, tea.Cmd, bool) {
	switch b.refreshing.phase {
	case refreshAsking:
		if key == "y" {
			return b, b.startFetch(), true
		}
		b.endAttempt("")
		return b, nil, true
	case refreshSizing, refreshFetching:
		switch key {
		case "esc":
			b.endAttempt("")
			b.refreshing.notice = "Refresh canceled; the results are those shown before it."
		case "q", "ctrl+c":
			b.endAttempt("")
			return b, tea.Quit, true
		}
		return b, nil, true
	}
	return b, nil, false
}

// replacedBy is the browser over report, the one matched again, on the tab
// that was showing and at the window's size.
func (b browser) replacedBy(report Report) browser {
	b.endAttempt("")
	next := newBrowser(report)
	next.width, next.height = b.width, b.height
	next.layout()
	next.showSelected()
	if len(b.tabs) > 0 {
		for i, t := range next.tabs {
			if t.id == b.tabs[b.active].id {
				next.selectTab(i)
			}
		}
	}
	return next
}

// refreshBody is what the body shows while a refresh asks or runs, or once
// one has failed: the plan and the question, the results faded under the
// progress line, or why it failed, until the next key.
func (b browser) refreshBody(body string) (string, bool) {
	switch b.refreshing.phase {
	case refreshAsking:
		// Each line is cut at the window's edge, as every line the browser
		// draws is, since a wrapped line would break the frame.
		lines := append([]string{"A refresh fetches:"}, b.refreshing.plan...)
		lines = append(lines, "", refreshQuestion)
		for i, line := range lines {
			lines[i] = truncate(line, max(b.width, 1))
		}
		return fitPane(styleText.Render(strings.Join(lines, "\n")), b.width, b.bodyHeight()), true
	case refreshSizing, refreshFetching:
		return styleMuted.Faint(true).Render(ansi.Strip(body)), true
	}
	if b.refreshing.failed != "" {
		// The reason is wrapped to the window in full, since what it says to
		// do is often at its end, where a cut line would lose it.
		reason := styleNotice.Render("The refresh failed:") + "\n\n" + styleText.Render(detailWrap(b.width).Render(b.refreshing.failed))
		return fitPane(reason, b.width, b.bodyHeight()), true
	}
	return body, false
}

// refreshFooter is the footer while a refresh runs or has just ended without
// replacing the report: the step under way, that a key returns to the
// results from why one failed, or the notice of one canceled.
func (b browser) refreshFooter() (string, bool) {
	switch {
	case b.refreshing.phase == refreshSizing:
		return truncate(styleText.Render("Sizing the datasets; esc cancels"), max(b.width, 1)), true
	case b.refreshing.phase == refreshFetching:
		line := b.refreshing.progress
		if line == "" {
			line = "Fetching"
		}
		return truncate(styleText.Render(line+"  (esc cancels)"), max(b.width, 1)), true
	case b.refreshing.failed != "":
		return truncate(styleNotice.Render("Refresh failed; any key returns to the results"), max(b.width, 1)), true
	case b.refreshing.notice != "":
		return truncate(styleNotice.Render(b.refreshing.notice), max(b.width, 1)), true
	}
	return "", false
}
