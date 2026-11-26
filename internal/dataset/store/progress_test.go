// internal/dataset/store/progress_test.go

package store

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

// recorded is a Progress that writes down what it is told, one line an event,
// with the last count of bytes received before each step ends.
type recorded struct {
	events   []string
	received int64
}

func (r *recorded) Began(id string, s Step, attempt int) {
	r.events = append(r.events, fmt.Sprintf("%s began %s %d", id, s, attempt))
}

func (r *recorded) Received(_ string, bytes int64) { r.received = bytes }

func (r *recorded) Ended(id string, s Step, err error) {
	state := "ok"
	if err != nil {
		state = "failed"
	}
	r.events = append(r.events, fmt.Sprintf("%s ended %s %s", id, s, state))
}

// tried is a pattern of the events of a step that succeeds: each attempt the
// store tried again, as it does when Windows holds a new file open for a
// moment, and the one that succeeded.
func tried(step string) string {
	return `(wanted began ` + step + ` \d\nwanted ended ` + step + ` (failed|ok)\n)*wanted began ` + step + ` \d\nwanted ended ` + step + ` ok\n`
}

// eventsMatch reports whether events are wholly what pattern describes.
func eventsMatch(events []string, pattern string) bool {
	return regexp.MustCompile(`^` + pattern + `$`).MatchString(strings.Join(events, "\n") + "\n")
}

// A refresh tells its progress of each step as it begins and ends: each
// attempt at the download, with what it has received, then the check and the
// install. The first download fails, as the test's fetch makes it; any other
// attempt is one the store makes by design.
func TestRefreshReportsEachStep(t *testing.T) {
	s, _ := stores(t)
	p := &recorded{}
	fetch, _ := serving(content, errBrief{})
	if o := refresh(t, s.Reporting(p), fetch); o.Result != Installed {
		t.Fatalf("outcome %+v", o)
	}
	want := "wanted began download 1\nwanted ended download failed\n" + tried("download") +
		"wanted began check 1\nwanted ended check ok\n" + tried("install")
	if !eventsMatch(p.events, want) {
		t.Errorf("events\n%s\ndo not match\n%s", strings.Join(p.events, "\n"), want)
	}
	if p.received != int64(len(content)) {
		t.Errorf("the download was reported at %d bytes, want %d", p.received, len(content))
	}
}

// An import tells its progress of the check and the install, and a store
// given no progress tells nothing and imports as before.
func TestImportReportsEachStep(t *testing.T) {
	s, src := stores(t)
	put(t, src, wanted, content, now.Add(-time.Hour), nil)
	p := &recorded{}
	if got := importFrom(t, s.Reporting(p), src); len(got) != 1 || got[0].Result != Installed {
		t.Fatalf("outcomes %+v", got)
	}
	if want := "wanted began check 1\nwanted ended check ok\n" + tried("install"); !eventsMatch(p.events, want) {
		t.Errorf("events %q do not match %q", p.events, want)
	}

	quietStore, src := stores(t)
	put(t, src, wanted, content, now.Add(-time.Hour), nil)
	if got := importFrom(t, quietStore, src); len(got) != 1 || got[0].Result != Installed {
		t.Errorf("a store with no progress imported %+v", got)
	}
}

// The pattern of a step takes one that succeeded at once and one the store
// tried again, and not one whose last attempt failed.
func TestTried(t *testing.T) {
	for events, want := range map[string]bool{
		"wanted began install 1|wanted ended install ok":                                                    true,
		"wanted began install 1|wanted ended install failed|wanted began install 2|wanted ended install ok": true,
		"wanted began install 1|wanted ended install ok|wanted began install 2|wanted ended install ok":     true,
		"wanted began install 1|wanted ended install failed":                                                false,
	} {
		if got := eventsMatch(strings.Split(events, "|"), tried("install")); got != want {
			t.Errorf("%q matched %v, want %v", events, got, want)
		}
	}
}
