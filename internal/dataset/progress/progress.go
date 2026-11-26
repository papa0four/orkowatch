// internal/dataset/progress/progress.go

// Package progress shows what a change of the dataset store is doing while it
// does it: the download of each dataset, with how much has been received of
// how much, for how long, and how fast, and each step after it. Over 800 MB
// can take minutes, and without this a download that is moving, one that has
// stalled, and one about to fail all look the same. On a terminal the line of
// the step under way is rewritten in place; anywhere else each step gets a
// line as it begins and as it ends, and nothing is rewritten.
package progress

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/store"
	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/tone"
)

const (
	// every is how often the line of the step under way is rewritten on a
	// terminal.
	every = 500 * time.Millisecond

	// quietShown is how long a download may receive nothing before its
	// line says how long it has been waiting. It is far below the time a
	// fetch gives up on a stalled download, so the wait shows before that.
	quietShown = 5 * time.Second

	// clearLine returns to the start of the line and clears it, so the next
	// text replaces the line in place.
	clearLine = "\r\x1b[K"
)

// Report is the progress of one change of the store, written to out. It is a
// store.Progress. width is how wide the terminal out is attached to is, and
// nil when out is not a terminal.
type Report struct {
	mu       sync.Mutex
	out      io.Writer
	width    func() int
	now      func() time.Time
	expected map[string]expected
	current  *running
	err      error
	stop     chan struct{}
	done     chan struct{}
}

// expected is how large a dataset's download is to be: its size as its
// server states it, or the most a fetch may read when the server does not
// say.
type expected struct {
	size   int64
	stated bool
}

// running is the step under way: its dataset, step and attempt, when it
// began, and for a download what has been received and when the last of it
// came. The store takes one step at a time.
type running struct {
	id       string
	step     store.Step
	attempt  int
	began    time.Time
	received int64
	last     time.Time
}

// New returns the progress of a change of the store written to out, timed by
// now. width is how wide the terminal out is attached to is, asked each time a
// line is rewritten in place; nil means out is not a terminal, and nothing is
// rewritten.
func New(out io.Writer, width func() int, now func() time.Time) *Report {
	return &Report{out: out, width: width, now: now, expected: map[string]expected{}}
}

// Expect records how large the download of the dataset id is to be: size as
// its server states it when stated is true, and otherwise the most a fetch may
// read.
func (r *Report) Expect(id string, size int64, stated bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expected[id] = expected{size: size, stated: stated}
}

// Start begins rewriting the line of the step under way, on a terminal. Stop
// ends it.
func (r *Report) Start() {
	if r.width == nil {
		return
	}
	r.stop, r.done = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(r.done)
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-r.stop:
				return
			case <-ticker.C:
				r.tick()
			}
		}
	}()
}

// Stop ends what Start began, and returns the first error writing the
// progress met.
func (r *Report) Stop() error {
	if r.stop != nil {
		close(r.stop)
		<-r.done
		r.stop = nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// Began shows that a step of the dataset id has begun.
func (r *Report) Began(id string, step store.Step, attempt int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	at := r.now()
	r.current = &running{id: id, step: step, attempt: attempt, began: at, last: at}
	if r.width != nil {
		r.rewrite(r.current.text(at, r.expected[id]))
		return
	}
	r.write(render.HostText(r.current.beginning(r.expected[id])) + "\n")
}

// Received records how much of the dataset id's download has come.
func (r *Report) Received(id string, bytes int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current == nil || r.current.id != id {
		return
	}
	r.current.received, r.current.last = bytes, r.now()
}

// Ended shows how a step of the dataset id ended, on a line of its own, in
// the error tone on a terminal when it failed.
func (r *Report) Ended(id string, step store.Step, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	current := r.current
	if current == nil || current.id != id || current.step != step {
		current = &running{id: id, step: step, attempt: 1, began: r.now()}
	}
	r.current = nil
	line := render.HostText(current.ending(r.now(), err))
	if r.width == nil {
		r.write(line + "\n")
		return
	}
	if err != nil {
		line = tone.Error.Render(line)
	}
	r.write(clearLine + line + "\n")
}

// tick rewrites the line of the step under way, on a terminal; where nothing
// can be rewritten it writes nothing.
func (r *Report) tick() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current != nil && r.width != nil {
		r.rewrite(r.current.text(r.now(), r.expected[r.current.id]))
	}
}

// rewrite replaces the line on the terminal with line, cut to fit the
// terminal's width, since a line that wraps cannot be replaced in place.
func (r *Report) rewrite(line string) {
	line = render.HostText(line)
	if room := r.width() - 1; room > 0 {
		if runes := []rune(line); len(runes) > room {
			line = string(runes[:room])
		}
	}
	r.write(clearLine + line)
}

// write writes text to out, keeping the first error, after which nothing more
// is written.
func (r *Report) write(text string) {
	if r.err != nil {
		return
	}
	_, r.err = io.WriteString(r.out, text)
}

// The words each step is shown with: as it is under way, and once it is done.
var (
	underWay = map[store.Step]string{
		store.StepDownload: "downloading",
		store.StepKeep:     "keeping the records this host needs",
		store.StepCheck:    "checking",
		store.StepInstall:  "installing",
	}
	finished = map[store.Step]string{
		store.StepDownload: "downloaded",
		store.StepKeep:     "kept the records this host needs",
		store.StepCheck:    "checked",
		store.StepInstall:  "installed",
	}
)

// name is the step with its attempt, when it is not the first.
func (c running) name(words map[store.Step]string) string {
	name := c.id + ": " + words[c.step]
	if c.attempt > 1 {
		name += fmt.Sprintf(" (attempt %d)", c.attempt)
	}
	return name
}

// beginning is the line a step begins with where nothing is rewritten: the
// step, and for a download how large it is to be.
func (c running) beginning(want expected) string {
	line := c.name(underWay)
	if c.step == store.StepDownload && want.size > 0 {
		line += " " + of(want)
	}
	return line
}

// text is the line of the step under way at now: the step, how long it has
// run, and for a download what has been received of what is to come, how
// fast, and how long nothing has come when that is a while.
func (c running) text(now time.Time, want expected) string {
	took := now.Sub(c.began)
	if c.step != store.StepDownload {
		return c.name(underWay) + ", " + seconds(took)
	}
	line := c.name(underWay) + " " + dataset.Size(c.received)
	if want.size > 0 {
		line += " of " + of(want)
	}
	line += ", " + seconds(took)
	if rate := rateOf(c.received, took); rate != "" {
		line += ", " + rate
	}
	if quiet := now.Sub(c.last); quiet >= quietShown {
		line += ", nothing received for " + seconds(quiet)
	}
	return line
}

// ending is the line a step ends with at now: what it did and how long it
// took, and for a download how much came and how fast, or why it failed.
func (c running) ending(now time.Time, err error) string {
	took := now.Sub(c.began)
	if err != nil {
		return fmt.Sprintf("%s failed after %s: %v", c.name(underWay), seconds(took), err)
	}
	if c.step != store.StepDownload {
		return c.name(finished) + " in " + seconds(took)
	}
	line := c.name(finished) + " " + dataset.Size(c.received) + " in " + seconds(took)
	if rate := rateOf(c.received, took); rate != "" {
		line += ", " + rate
	}
	return line
}

// of is how large a download is to be, as a line says it.
func of(want expected) string {
	if want.stated {
		return dataset.Size(want.size)
	}
	return "up to " + dataset.Size(want.size)
}

// seconds is a time as a line says it, to the second.
func seconds(d time.Duration) string {
	return d.Round(time.Second).String()
}

// rateOf is how fast bytes came in took, or nothing before a second has
// passed, when a rate would mean little.
func rateOf(bytes int64, took time.Duration) string {
	if took < time.Second {
		return ""
	}
	return dataset.Size(int64(float64(bytes)/took.Seconds())) + "/s"
}
