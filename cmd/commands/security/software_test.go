// cmd/commands/security/software_test.go

package security

import (
	"slices"
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/softwarelist"
	"github.com/papa0four/orkowatch/internal/tui"
	"github.com/papa0four/orkowatch/internal/vulnmatch"
)

// inventory is a dpkg host: two binaries of openssl, bash, coreutils, which
// nothing is matched to, and a package of another manager.
func inventory() softwarelist.SoftwareView {
	return softwarelist.View([]softwarelist.SoftwareEntry{
		{Name: "bash", Version: "5.1-6ubuntu1", Manager: "dpkg", Source: "bash", SourceVersion: "5.1-6ubuntu1"},
		{Name: "coreutils", Version: "8.32-4", Manager: "dpkg", Source: "coreutils", SourceVersion: "8.32-4"},
		{Name: "libssl3", Version: "3.0.2-1", Manager: "dpkg", Source: "openssl", SourceVersion: "3.0.2-1"},
		{Name: "openssl", Version: "3.0.2-1", Manager: "dpkg", Source: "openssl", SourceVersion: "3.0.2-1"},
		{Name: "snapd-thing", Version: "1.0", Manager: "rpm"},
	})
}

// record returns the record titled title.
func recordOf(t *testing.T, tab tui.Tab, title string) tui.Record {
	t.Helper()
	for _, r := range tab.Records {
		if r.Title == title {
			return r
		}
	}
	t.Fatalf("no record %q", title)
	return tui.Record{}
}

// Each package of the manager matched shows its counts and worst severity,
// joined to its match by the source the records name, so both binaries of
// openssl share its vulnerabilities; its detail lists them in the match's order;
// it falls under affected, and under fix available when one has a fix; a
// package nothing is matched to says so without being called clean; and one
// of another manager is left as the inventory has it.
func TestSoftwareTabCounts(t *testing.T) {
	v := matchedView()
	v.Order = "dpkg"
	tab := softwareTab(inventory(), &v)

	for _, name := range []string{"libssl3", "openssl"} {
		r := recordOf(t, tab, name)
		if r.Subtitle != "3.0.2-1  1 fixable, 1 unfixed; worst Important" || !slices.Equal(r.Filters[0], []string{"affected", "fix available"}) {
			t.Errorf("%s: %q under %q", name, r.Subtitle, r.Filters)
		}
		if got := field(r, "matched against osv-ubuntu, Ubuntu:22.04, data of 2026-11-24, current"); got != "CVE-2026-1  fix 3.0.2-2  Important\nCVE-2026-2  unfixed  low" {
			t.Errorf("%s lists %q", name, got)
		}
	}
	if r := recordOf(t, tab, "bash"); r.Subtitle != "5.1-6ubuntu1  1 unfixed" || !slices.Equal(r.Filters[0], []string{"affected"}) {
		t.Errorf("bash: %q under %q", r.Subtitle, r.Filters)
	}
	if r := recordOf(t, tab, "coreutils"); r.Subtitle != "8.32-4" || len(r.Filters[0]) != 0 || !strings.Contains(field(r, "vulnerabilities"), "does not say the package has none") {
		t.Errorf("coreutils: %q under %q, %q", r.Subtitle, r.Filters, field(r, "vulnerabilities"))
	}
	if r := recordOf(t, tab, "snapd-thing"); r.Subtitle != "1.0" || len(r.Filters[0]) != 0 || field(r, "vulnerabilities") != "" {
		t.Errorf("a package of another manager: %+v", r)
	}

	if len(tab.Filters) != 1 || !slices.Equal(tab.Filters[0].Options, []string{tui.All, "affected", "fix available"}) || tab.Filters[0].Start != tui.All {
		t.Errorf("filters %+v", tab.Filters)
	}
	if want := (tui.Switch{Key: "a", Filter: "vulnerabilities", A: tui.All, B: "affected", Hint: "affected or all"}); tab.Switch != want {
		t.Errorf("switch %+v", tab.Switch)
	}
}

// With no match made the tab is the inventory, with no filter and no switch,
// and each package says why; with no match in the report at all it is the
// inventory alone.
func TestSoftwareTabWithoutAMatch(t *testing.T) {
	tab := softwareTab(inventory(), &vulnmatch.View{Use: dataset.Use{NotDone: "osv-ubuntu is not held"}})
	if r := recordOf(t, tab, "bash"); len(tab.Filters) != 0 || tab.Switch.Key != "" || r.Subtitle != "5.1-6ubuntu1" ||
		field(r, "vulnerabilities") != "Matching was not done: osv-ubuntu is not held" {
		t.Errorf("with no match made: filters %+v, switch %+v, record %+v", tab.Filters, tab.Switch, r)
	}
	tab = softwareTab(inventory(), nil)
	if r := recordOf(t, tab, "bash"); len(tab.Filters) != 0 || field(r, "vulnerabilities") != "" || len(r.Filters) != 0 {
		t.Errorf("with no match in the report: %+v, %+v", tab.Filters, r)
	}
}
