// internal/dataset/limit_test.go

package dataset

import (
	"io"
	"strings"
	"testing"
)

// A source read within a limit counts what was read and is past the limit
// only when it held more than the limit: at the limit it is not, and one byte
// more is read and counted so it can be told apart.
func TestLimited(t *testing.T) {
	for source, past := range map[string]bool{"": false, "abc": false, "abcd": false, "abcde": true, "abcdefgh": true} {
		c := Limited(strings.NewReader(source), 4)
		got, err := io.ReadAll(c)
		if err != nil {
			t.Fatal(err)
		}
		if want := min(len(source), 5); len(got) != want || c.N() != int64(want) || c.Past() != past {
			t.Errorf("%q: read %d, counted %d, past %v; want %d and past %v", source, len(got), c.N(), c.Past(), want, past)
		}
	}
}
