//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/fspath/open_unix_test.go

package fspath

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO is refused, and at once: an open that waited for a writer would hang
// a run on a file planted for that.
func TestOpenRegularRefusesAFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("no FIFO can be made here: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := OpenRegular(fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Errorf("a FIFO gave %v, want ErrNotRegular", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the open is waiting on the FIFO")
	}
}
