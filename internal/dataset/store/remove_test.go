// internal/dataset/store/remove_test.go

package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Removing a dataset deletes it, with its failure record, and leaves every
// other dataset as it was; a name the store does not hold, a path, and the
// lock are refused.
func TestRemove(t *testing.T) {
	s, _ := stores(t)
	put(t, s, wanted, content, now.Add(-time.Hour), nil)
	put(t, s, testDataset{id: "other"}, content, now.Add(-time.Hour), nil)
	if err := s.recordFailure("wanted", failure{Attempts: 1, Reason: "for the test", At: now}); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(s.root, "Not_A_Name")
	if err := os.Mkdir(unknown, 0o700); err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{"wanted", "Not_A_Name"} {
		if err := s.Remove(context.Background(), id); err != nil {
			t.Fatalf("remove %s: %v", id, err)
		}
		if _, err := os.Lstat(s.dir(id)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is still there: %v", id, err)
		}
	}
	if _, err := os.Stat(s.dir("other")); err != nil {
		t.Errorf("another dataset was touched: %v", err)
	}

	outside := filepath.Join(filepath.Dir(s.root), "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"wanted", "absent", "", ".lock", "..", "../outside", "other/" + manifestName, `other\x`} {
		if err := s.Remove(context.Background(), id); !errors.Is(err, ErrNotHeld) {
			t.Errorf("remove %q gave %v, want ErrNotHeld", id, err)
		}
	}
	for _, path := range []string{filepath.Join(s.dir("other"), manifestName), outside} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("a refused removal touched %s: %v", path, err)
		}
	}
}

// A link in the store is not a dataset and is not followed: removing it by
// name is refused, and what it points to is left.
func TestRemoveRefusesALink(t *testing.T) {
	s, _ := stores(t)
	put(t, s, wanted, content, now.Add(-time.Hour), nil)
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, s.dir("linked")); err != nil {
		t.Skipf("this account cannot make a link: %v", err)
	}
	if err := s.Remove(context.Background(), "linked"); !errors.Is(err, ErrNotHeld) {
		t.Errorf("remove of a link gave %v, want ErrNotHeld", err)
	}
	if _, err := os.Stat(elsewhere); err != nil {
		t.Errorf("what the link points to was removed: %v", err)
	}
}
