// internal/tui/model_test.go

package tui

import (
	"testing"
	"time"
)

// The clock shows milliseconds, so a check that takes less than a second does
// not read as taking none.
func TestClock(t *testing.T) {
	cases := map[time.Duration]string{
		0:                                    "00:00.000",
		7 * time.Millisecond:                 "00:00.007",
		7*time.Second + 250*time.Millisecond: "00:07.250",
		61*time.Second + 999*time.Millisecond + 999*time.Microsecond: "01:01.999",
		75 * time.Minute: "75:00.000",
	}
	for d, want := range cases {
		if got := clock(d); got != want {
			t.Errorf("clock(%v) = %q, want %q", d, got, want)
		}
	}
}
