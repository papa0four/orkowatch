// internal/dataset/store/protected_test.go

package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/elevation"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

// guard is a protection a test controls: it records what was begun, ended,
// and made, and calls a directory open when open names it.
type guard struct {
	begun, ended int
	made         []string
	open         map[string]string
}

// guarded returns a protected store in a directory of the test's, with the
// guard that stands in for the host's protection, which needs an elevated
// process.
func guarded(t *testing.T) (Store, *guard) {
	t.Helper()
	g := &guard{open: map[string]string{}}
	s := Store{root: filepath.Join(t.TempDir(), "owatch", "datasets"), protect: &protection{
		begin: func() (func() error, error) {
			g.begun++
			return func() error { g.ended++; return nil }, nil
		},
		make: func(dir string) error {
			g.made = append(g.made, dir)
			return os.Mkdir(dir, dirMode)
		},
		judge: func(dir string) (string, error) {
			if _, err := os.Lstat(dir); err != nil {
				return "", err
			}
			return g.open[dir], nil
		},
	}}
	return s, g
}

// A protected store is made one directory at a time, each as its protection
// makes it, under what the protection begins and ends around the change; a
// store already there is not made again.
func TestProtectedStoreIsMadeProtected(t *testing.T) {
	s, g := guarded(t)
	src := Store{root: t.TempDir()}
	put(t, src, wanted, content, now.Add(-time.Hour), nil)

	if got := importFrom(t, s, src); len(got) != 1 || got[0].Result != Installed {
		t.Fatalf("outcomes %+v", got)
	}
	if want := []string{filepath.Dir(s.root), s.root}; !slices.Equal(g.made, want) {
		t.Errorf("made %q, want %q", g.made, want)
	}
	if g.begun != 1 || g.ended != 1 {
		t.Errorf("begun %d and ended %d, want once each", g.begun, g.ended)
	}
	if row := rowOf(t, s, known, "wanted"); row.State != dataset.StateCurrent {
		t.Errorf("row %+v, want the dataset current", row)
	}

	importFrom(t, s, src)
	if len(g.made) != 2 || g.begun != 2 || g.ended != 2 {
		t.Errorf("a second import made %q, begun %d, ended %d", g.made, g.begun, g.ended)
	}
}

// An elevated run never reads a dataset from a directory someone who is not
// an administrator can change: with the store's own directory or the one
// above it open, status, import, and remove refuse and nothing is read or
// written; with a dataset's directory open, that dataset is unusable and the
// others are read.
func TestProtectedStoreIsNeverReadWhenOpen(t *testing.T) {
	host := &osfingerprint.OSInfo{}
	other := testDataset{Name: "other", Applies: true}
	both := []dataset.Dataset{wanted, other}

	for _, which := range []string{"the store", "the directory above it"} {
		s, g := guarded(t)
		src := Store{root: t.TempDir()}
		put(t, src, wanted, content, now.Add(-time.Hour), nil)
		importFrom(t, s, src)
		dir := s.root
		if which != "the store" {
			dir = filepath.Dir(s.root)
		}
		g.open[dir] = "writable by another"
		begun := g.begun

		if _, err := s.Status(known, host, now); !errors.Is(err, ErrOpen) || !strings.Contains(err.Error(), dir+" is writable by another") {
			t.Errorf("%s open: status gave %v, want ErrOpen naming it", which, err)
		}
		if _, err := s.Import(context.Background(), src.root, known, host, now.Add(time.Hour)); !errors.Is(err, ErrOpen) {
			t.Errorf("%s open: import gave %v, want ErrOpen", which, err)
		}
		if err := s.Remove(context.Background(), "wanted"); !errors.Is(err, ErrOpen) {
			t.Errorf("%s open: remove gave %v, want ErrOpen", which, err)
		}
		if !slices.Contains(names(t, s, "wanted"), manifestName) {
			t.Errorf("%s open: the dataset was removed", which)
		}
		if g.ended != g.begun || g.begun == begun {
			t.Errorf("%s open: begun %d and ended %d after %d, want each refusal begun and ended", which, g.begun, g.ended, begun)
		}
	}

	s, g := guarded(t)
	src := Store{root: t.TempDir()}
	put(t, src, wanted, content, now.Add(-time.Hour), nil)
	put(t, src, other, content, now.Add(-time.Hour), nil)
	if _, err := s.Import(context.Background(), src.root, both, host, now); err != nil {
		t.Fatal(err)
	}
	g.open[s.dir("wanted")] = "owned by another"
	if row := rowOf(t, s, both, "wanted"); row.State != dataset.StateUnusable || !strings.Contains(row.Reason, "is owned by another") || row.DataDate != "" {
		t.Errorf("a dataset in an open directory: %+v, want it unusable and unread", row)
	}
	if row := rowOf(t, s, both, "other"); row.State != dataset.StateCurrent {
		t.Errorf("the dataset beside it: %+v, want it current", row)
	}
}

// The account's own store, and a directory to carry, are made as before and
// judged by nothing.
func TestUnprotectedStoreIsNotJudged(t *testing.T) {
	s, src := stores(t)
	put(t, src, wanted, content, now.Add(-time.Hour), nil)
	if got := importFrom(t, s, src); len(got) != 1 || got[0].Result != Installed {
		t.Fatalf("outcomes %+v", got)
	}
	if err := s.judged(s.dir("wanted")); err != nil {
		t.Errorf("an unprotected store was judged: %v", err)
	}
}

// On this host, as an elevated process, the protected store's own making
// gives directories the host's rule accepts, and what is made in them under
// the store's lock passes it too. It needs an elevated process and says so
// where the test is not one.
func TestProtectionOnThisHost(t *testing.T) {
	if !elevation.Elevated() {
		t.Skip("making a directory only administrators may change takes an elevated process")
	}
	s := Store{root: filepath.Join(t.TempDir(), "owatch", "datasets"),
		protect: &protection{begin: beginProtected, make: makeProtected, judge: elevation.OpenBeyondAdmins}}
	src := Store{root: t.TempDir()}
	put(t, src, wanted, content, now.Add(-time.Hour), nil)

	// The directory the test makes the store in is the account's, as the
	// system's data directory is not, so only what the store made is judged.
	if got := importFrom(t, s, src); len(got) != 1 || got[0].Result != Installed {
		t.Fatalf("outcomes %+v", got)
	}
	for _, dir := range []string{filepath.Dir(s.root), s.root, s.dir("wanted")} {
		if reason, err := elevation.OpenBeyondAdmins(dir); err != nil || reason != "" {
			t.Errorf("%s: %q, %v; want it closed to all but administrators", dir, reason, err)
		}
	}
	if row := rowOf(t, s, known, "wanted"); row.State != dataset.StateCurrent {
		t.Errorf("row %+v, want the dataset current", row)
	}
}
