// internal/notices/notices_test.go

package notices

import (
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/epss"
	"github.com/papa0four/orkowatch/internal/dataset/kev"
)

// The notices state the address each dataset owatch reads but does not carry
// is fetched from, and the attribution every report that reads it states, as
// the dataset itself gives them, so the two cannot drift apart.
func TestNoticesStateWhatReportsAttribute(t *testing.T) {
	for _, d := range []dataset.Dataset{epss.Scores{}, kev.Catalog{}} {
		origin := d.Origin()
		if !strings.Contains(Text(), origin.URL) || !strings.Contains(Text(), origin.Attribution) {
			t.Errorf("the notices do not state %s's address %q and attribution %q", d.ID(), origin.URL, origin.Attribution)
		}
	}
}
