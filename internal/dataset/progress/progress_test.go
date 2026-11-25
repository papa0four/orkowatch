// internal/dataset/progress/progress_test.go

package progress

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset/store"
)

// clock is a time a test moves by hand.
type clock struct{ at time.Time }

func (c *clock) now() time.Time       { return c.at }
func (c *clock) pass(d time.Duration) { c.at = c.at.Add(d) }

// wide is a terminal wide enough for any line.
func wide() int { return 200 }

// lastLine is what was written after the last clearing of the line.
func lastLine(text string) string {
	return text[strings.LastIndex(text, clearLine)+len(clearLine):]
}

// mib is n mebibytes.
func mib(n int64) int64 { return n << 20 }

// reportOn returns a report written to a buffer on a terminal width says the
// width of, or none when width is nil, timed by a clock the test moves.
func reportOn(width func() int) (*Report, *strings.Builder, *clock) {
	var out strings.Builder
	c := &clock{at: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)}
	return New(&out, width, c.now), &out, c
}

// On a terminal a download's line is rewritten in place with what has come of
// what is to come, for how long, and how fast; a download that receives
// nothing for a while says how long it has waited; and the step ends on a line
// of its own.
func TestTerminalDownload(t *testing.T) {
	r, out, c := reportOn(wide)
	r.Expect("osv-ubuntu", mib(845), true)
	r.Began("osv-ubuntu", store.StepDownload, 1)

	c.pass(10 * time.Second)
	r.Received("osv-ubuntu", mib(100))
	r.tick()
	if got, want := lastLine(out.String()), "osv-ubuntu: downloading 100.0 MiB of 845.0 MiB, 10s, 10.0 MiB/s"; got != want {
		t.Errorf("under way: %q, want %q", got, want)
	}

	c.pass(20 * time.Second)
	r.tick()
	if got, want := lastLine(out.String()), "osv-ubuntu: downloading 100.0 MiB of 845.0 MiB, 30s, 3.3 MiB/s, nothing received for 20s"; got != want {
		t.Errorf("stalled: %q, want %q", got, want)
	}

	r.Ended("osv-ubuntu", store.StepDownload, nil)
	if got, want := lastLine(out.String()), "osv-ubuntu: downloaded 100.0 MiB in 30s, 3.3 MiB/s\n"; got != want {
		t.Errorf("ended: %q, want %q", got, want)
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
}

// Where nothing can be rewritten, each step gets a line as it begins and as it
// ends, and a later attempt and a failure say so.
func TestPlainLines(t *testing.T) {
	r, out, c := reportOn(nil)
	r.Expect("epss", mib(32), false)
	r.Began("epss", store.StepDownload, 2)
	c.pass(time.Minute)
	r.Ended("epss", store.StepDownload, errors.New("the download stalled"))
	r.Began("epss", store.StepCheck, 1)
	c.pass(4 * time.Second)
	r.tick()
	r.Ended("epss", store.StepCheck, nil)

	want := "epss: downloading (attempt 2) up to 32.0 MiB\n" +
		"epss: downloading (attempt 2) failed after 1m0s: the download stalled\n" +
		"epss: checking\n" +
		"epss: checked in 4s\n"
	if out.String() != want {
		t.Errorf("wrote\n%s\nwant\n%s", out.String(), want)
	}
	if strings.ContainsAny(out.String(), "\r\x1b") {
		t.Errorf("rewrote a line where nothing can be: %q", out.String())
	}
}

// A line rewritten in place is cut to the terminal's width, since one that
// wraps cannot be replaced.
func TestRewriteFitsTheTerminal(t *testing.T) {
	r, out, _ := reportOn(func() int { return 20 })
	r.Began("osv-ubuntu", store.StepKeep, 1)
	if got := lastLine(out.String()); got != "osv-ubuntu: keeping" {
		t.Errorf("rewrote %q on a terminal 20 columns wide", got)
	}
}

// Start and Stop rewrite the line from their own goroutine and end it
// cleanly; where nothing is rewritten, they start nothing.
func TestStartAndStop(t *testing.T) {
	for _, width := range []func() int{wide, nil} {
		r, _, _ := reportOn(width)
		r.Start()
		r.Began("kev", store.StepInstall, 1)
		r.Ended("kev", store.StepInstall, nil)
		if err := r.Stop(); err != nil {
			t.Fatal(err)
		}
	}
}
