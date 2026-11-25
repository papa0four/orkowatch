// internal/dataset/store/progress_test.go

package store

import (
	"fmt"
	"slices"
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

// A refresh tells its progress of each step as it begins and ends: each
// attempt at the download, with what it has received, then the check and the
// install.
func TestRefreshReportsEachStep(t *testing.T) {
	s, _ := stores(t)
	p := &recorded{}
	fetch, _ := serving(content, errBrief{})
	if o := refresh(t, s.Reporting(p), fetch); o.Result != Installed {
		t.Fatalf("outcome %+v", o)
	}
	want := []string{
		"wanted began download 1", "wanted ended download failed",
		"wanted began download 2", "wanted ended download ok",
		"wanted began check 1", "wanted ended check ok",
		"wanted began install 1", "wanted ended install ok",
	}
	if !slices.Equal(p.events, want) {
		t.Errorf("events\n%s\nwant\n%s", strings.Join(p.events, "\n"), strings.Join(want, "\n"))
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
	want := []string{"wanted began check 1", "wanted ended check ok", "wanted began install 1", "wanted ended install ok"}
	if !slices.Equal(p.events, want) {
		t.Errorf("events %q, want %q", p.events, want)
	}

	quietStore, src := stores(t)
	put(t, src, wanted, content, now.Add(-time.Hour), nil)
	if got := importFrom(t, quietStore, src); len(got) != 1 || got[0].Result != Installed {
		t.Errorf("a store with no progress imported %+v", got)
	}
}
