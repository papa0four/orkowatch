// internal/tui/refresh_test.go

package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

// planned is what the fake refresh says it would fetch.
var planned = []string{"epss: 2.7 MiB from https://data.example/epss, allowed 10m0s"}

// fakeRefresher plans planned, or fails with planErr, and fetches by calling
// fetch, counting how often it was asked to.
type fakeRefresher struct {
	planErr error
	fetch   func(ctx context.Context, line func(string)) (Report, error)
	fetches int
}

func (f *fakeRefresher) Plan(context.Context) ([]string, error) {
	if f.planErr != nil {
		return nil, f.planErr
	}
	return planned, nil
}

func (f *fakeRefresher) Fetch(ctx context.Context, line func(string)) (Report, error) {
	f.fetches++
	return f.fetch(ctx, line)
}

// refreshable is a browser over a report with refresh, sized to show it.
func refreshable(refresh Refresher) browser {
	report := sidebarReport(2)
	report.Refresh = refresh
	return sized(newBrowser(report), 120, 30)
}

// pressing presses key and returns the browser with the command it gave.
func pressing(b browser, key string) (browser, tea.Cmd) {
	m, cmd := b.onKey(tea.KeyPressMsg{Code: rune(key[0]), Text: key})
	return m.(browser), cmd
}

// settle runs cmd and feeds what it gives back into the browser until no
// command is left, returning the browser and whether it quit.
func settle(t *testing.T, b browser, cmd tea.Cmd) (browser, bool) {
	t.Helper()
	for cmd != nil {
		msg := cmd()
		if _, ok := msg.(tea.QuitMsg); ok {
			return b, true
		}
		var m tea.Model
		m, cmd = b.Update(msg)
		b = m.(browser)
	}
	return b, false
}

// A report with no refresh offers no r: the key does nothing and no hint
// names it.
func TestNoRefreshWithoutARefresher(t *testing.T) {
	b := sized(newBrowser(sidebarReport(2)), 120, 30)
	b, cmd := pressing(b, "r")
	if cmd != nil || b.refreshing.phase != refreshIdle || strings.Contains(plain(b.render()), "refresh") {
		t.Errorf("r with no refresher: phase %v, command %v", b.refreshing.phase, cmd != nil)
	}
}

// r names what would be fetched and asks; anything but y fetches nothing.
func TestRefreshAsksFirst(t *testing.T) {
	refresh := &fakeRefresher{fetch: func(context.Context, func(string)) (Report, error) { return Report{}, nil }}
	b := refreshable(refresh)
	if !strings.Contains(plain(b.helpView()), "(r) refresh") {
		t.Errorf("the hints do not name r: %q", plain(b.helpView()))
	}
	b, cmd := pressing(b, "r")
	b, _ = settle(t, b, cmd)
	screen := plain(b.render())
	if b.refreshing.phase != refreshAsking || !strings.Contains(screen, planned[0]) || !strings.Contains(screen, "Fetch these and match again? [y/N]") {
		t.Fatalf("after r: phase %v, screen\n%s", b.refreshing.phase, screen)
	}
	b, cmd = pressing(b, "n")
	if cmd != nil || b.refreshing.phase != refreshIdle || refresh.fetches != 0 {
		t.Errorf("answered no: phase %v, fetched %d times", b.refreshing.phase, refresh.fetches)
	}
}

// Yes fetches with the progress shown, then replaces the report, staying on
// the tab that was showing.
func TestRefreshReplacesTheReport(t *testing.T) {
	var shown string
	refresh := &fakeRefresher{}
	b := refreshable(refresh)
	refresh.fetch = func(_ context.Context, line func(string)) (Report, error) {
		line("epss: downloading 1.0 MiB of 2.7 MiB, 1s")
		report := sidebarReport(3)
		report.Title = "owatch software"
		report.Refresh = refresh
		return report, nil
	}
	b = press(b, "s")
	b, cmd := pressing(b, "r")
	b, _ = settle(t, b, cmd)
	b, cmd = pressing(b, "y")
	if b.refreshing.phase != refreshFetching {
		t.Fatalf("after yes the phase is %v", b.refreshing.phase)
	}
	// The first message is the progress line, drawn under the faded results.
	m, cmd := b.Update(cmd())
	b = m.(browser)
	shown = plain(b.render())
	if !strings.Contains(shown, "epss: downloading 1.0 MiB of 2.7 MiB, 1s") {
		t.Errorf("the progress line is not shown:\n%s", shown)
	}
	b, _ = settle(t, b, cmd)
	if b.report.Title != "owatch software" || len(b.report.Items) != 3 || b.refreshing.phase != refreshIdle || b.tabs[b.active].id != TabSoftware {
		t.Errorf("after the fetch: title %q, %d items, phase %v, tab %s", b.report.Title, len(b.report.Items), b.refreshing.phase, b.tabs[b.active].id)
	}
	if b.width != 120 || b.height != 30 || b.report.Refresh == nil {
		t.Errorf("the replaced browser is %dx%d, refresh %v", b.width, b.height, b.report.Refresh != nil)
	}
}

// A fetch that fails keeps the results on screen with the reason, until the
// next key.
func TestRefreshFailureKeepsTheResults(t *testing.T) {
	refresh := &fakeRefresher{fetch: func(context.Context, func(string)) (Report, error) {
		return Report{}, errors.New("1 of 3 datasets not refreshed")
	}}
	b := refreshable(refresh)
	b, cmd := pressing(b, "r")
	b, _ = settle(t, b, cmd)
	b, cmd = pressing(b, "y")
	b, _ = settle(t, b, cmd)
	if b.report.Title != "owatch all" || len(b.report.Items) != 2 || !strings.Contains(plain(b.render()), "Refresh failed: 1 of 3 datasets not refreshed") {
		t.Errorf("after a failure: title %q, screen\n%s", b.report.Title, plain(b.render()))
	}
	if b = press(b, "j"); strings.Contains(plain(b.render()), "Refresh failed") {
		t.Error("the reason stayed after the next key")
	}
}

// esc during the fetch cancels it, keeps the results, and says so; what the
// canceled fetch gives later is not taken, even a report it finished as it
// was canceled.
func TestRefreshCanceled(t *testing.T) {
	started := make(chan struct{})
	refresh := &fakeRefresher{fetch: func(ctx context.Context, _ func(string)) (Report, error) {
		close(started)
		<-ctx.Done()
		return Report{Title: "late"}, nil
	}}
	b := refreshable(refresh)
	b, cmd := pressing(b, "r")
	b, _ = settle(t, b, cmd)
	b, cmd = pressing(b, "y")
	<-started
	b = pressCode(b, tea.KeyEscape)
	if b.refreshing.phase != refreshIdle || !strings.Contains(plain(b.render()), "Refresh canceled") {
		t.Errorf("after esc: phase %v, screen\n%s", b.refreshing.phase, plain(b.render()))
	}
	b, _ = settle(t, b, cmd)
	if b.report.Title != "owatch all" || !strings.Contains(plain(b.render()), "Refresh canceled") {
		t.Errorf("the canceled fetch replaced the report with %q, screen\n%s", b.report.Title, plain(b.render()))
	}
}

// A plan that cannot be made here closes the browser, leaving the text for
// the command to print.
func TestRefreshLeaves(t *testing.T) {
	refresh := &fakeRefresher{planErr: Leave{Text: "Run owatch data refresh as the account behind this run."}}
	b := refreshable(refresh)
	b, cmd := pressing(b, "r")
	b, quit := settle(t, b, cmd)
	if !quit || b.leave == nil || b.leave.Text != "Run owatch data refresh as the account behind this run." || refresh.fetches != 0 {
		t.Errorf("quit %v, leave %+v, fetched %d times", quit, b.leave, refresh.fetches)
	}
}
