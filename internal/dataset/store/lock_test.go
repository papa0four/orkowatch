// internal/dataset/store/lock_test.go

package store

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// holderEnv names the store a test process run as a lock holder locks.
const holderEnv = "OWATCH_TEST_LOCK_HOLDER"

// TestLockHolder is not a test of its own: run with holderEnv set, it takes
// the lock of the store named there, says so, and waits to be killed.
func TestLockHolder(t *testing.T) {
	root := os.Getenv(holderEnv)
	if root == "" {
		t.Skip("run only as the lock holder of another test")
	}
	if _, err := (Store{root: root}).lock(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stdout.WriteString("held\n"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Minute)
}

// A second process waits for the lock and then gives up, and a holder that is
// killed leaves the lock free for the next.
func TestLockWaitsAndSurvivesAKilledHolder(t *testing.T) {
	s := Store{root: filepath.Join(t.TempDir(), "store")}
	holder := exec.Command(os.Args[0], "-test.run=^TestLockHolder$") // #nosec G204 -- this test binary, run again as the lock holder
	holder.Env = append(os.Environ(), holderEnv+"="+s.root)
	out, err := holder.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	ended := false
	t.Cleanup(func() {
		if !ended {
			if err := holder.Process.Kill(); err != nil {
				t.Error(err)
			}
			endedByKill(t, holder)
		}
	})
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || line != "held\n" {
		t.Fatalf("the holder said %q, %v", line, err)
	}

	const wait = 300 * time.Millisecond
	started := time.Now()
	if _, err := s.lock(context.Background(), wait); !errors.Is(err, ErrBusy) {
		t.Fatalf("a held lock gave %v, want ErrBusy", err)
	}
	if waited := time.Since(started); waited < wait {
		t.Errorf("gave up after %v, before the %v wait", waited, wait)
	}

	if err := holder.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	endedByKill(t, holder)
	ended = true

	release, err := s.lock(context.Background(), 0)
	if err != nil {
		t.Fatalf("the lock of a killed holder was not released: %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

// endedByKill waits for a holder that was killed, which ends it with an exit
// status and nothing else.
func endedByKill(t *testing.T, holder *exec.Cmd) {
	t.Helper()
	var exit *exec.ExitError
	if err := holder.Wait(); !errors.As(err, &exit) {
		t.Errorf("the killed holder ended with %v", err)
	}
}

// A lock released is free to take again at once.
func TestLockReleases(t *testing.T) {
	s := Store{root: filepath.Join(t.TempDir(), "store")}
	for range 2 {
		release, err := s.lock(context.Background(), 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := release(); err != nil {
			t.Fatal(err)
		}
	}
}
