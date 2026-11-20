// internal/tui/tui_test.go

package tui

import (
	"context"
	"errors"
	"testing"
	"time"
)

// How a run ended is read when its work returns. Work that returns inside
// its deadline finished, however long afterwards the deadline passes while
// its results are being read; work the deadline cut short timed out; and a
// context cancelled for another reason is not a timeout.
func TestRunReadsTheEndingWhenTheWorkReturns(t *testing.T) {
	const deadline = 50 * time.Millisecond
	quick := func(context.Context, Reporter) error { return nil }
	untilCancelled := func(ctx context.Context, _ Reporter) error {
		<-ctx.Done()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	ending, err := Run(ctx, Options{}, quick)
	<-ctx.Done()
	if err != nil || ending != Finished {
		t.Errorf("work that returned inside its deadline, read after the deadline passed: %v, %v", ending, err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), deadline)
	defer cancel()
	if ending, err := Run(ctx, Options{}, untilCancelled); err != nil || ending != TimedOut {
		t.Errorf("work the deadline cut short: %v, %v", ending, err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if ending, err := Run(ctx, Options{}, untilCancelled); err != nil || ending != Finished {
		t.Errorf("work whose context was cancelled with no deadline: %v, %v", ending, err)
	}

	failed := errors.New("the work failed")
	if _, err := Run(context.Background(), Options{}, func(context.Context, Reporter) error { return failed }); !errors.Is(err, failed) {
		t.Errorf("work that failed: %v", err)
	}
}
