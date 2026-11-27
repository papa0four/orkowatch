// internal/notices/notices_test.go

package notices

import (
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/dataset/epss"
	"github.com/papa0four/orkowatch/internal/dataset/fedora"
	"github.com/papa0four/orkowatch/internal/dataset/kev"
	"github.com/papa0four/orkowatch/internal/dataset/vuxml"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

// The notices state the address each dataset owatch reads but does not carry
// is fetched from, and the attribution every report that reads it states, as
// the dataset itself gives them, so the two cannot drift apart. A dataset
// fetched from an address of the host's release is stated by that address
// with <release> in place of the release, which the address for a host of
// that release must be; one asked by a query is stated without the query.
func TestNoticesStateWhatReportsAttribute(t *testing.T) {
	fedora44 := &osfingerprint.OSInfo{OS: "linux", Platform: "fedora", PlatformVersion: "44"}
	for _, tt := range []struct {
		d       dataset.Dataset
		host    *osfingerprint.OSInfo
		release string
	}{
		{epss.Scores{}, nil, ""},
		{kev.Catalog{}, nil, ""},
		{vuxml.Document{}, nil, ""},
		{fedora.Updates{}, fedora44, "44"},
		{fedora.TrackingBugs{}, fedora44, ""},
	} {
		origin := tt.d.Origin(tt.host)
		stated, _, _ := strings.Cut(origin.URL, "?")
		if tt.release != "" {
			stated = strings.Replace(stated, "/"+tt.release+"/", "/<release>/", 1)
		}
		if !strings.Contains(Text(), stated) || !strings.Contains(Text(), origin.Attribution) {
			t.Errorf("the notices do not state %s's address %q and attribution %q", tt.d.ID(), stated, origin.Attribution)
		}
	}
}
