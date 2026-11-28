//go:build linux

// internal/dataset/fedora/live_linux_test.go

// The updateinfo as dnf reads it, set against the matching of owatch, on a
// Fedora host with dnf: the same release's updates, the same installed
// packages, and the advisories each finds for them must be the same. It runs
// where FEDORA_UPDATEINFO names the updateinfo of the host's release, kept as
// fetched, and dnf5 is on the machine, and is skipped elsewhere.

package fedora

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/softwarelist"
	"github.com/papa0four/orkowatch/internal/vulnmatch"
	"github.com/papa0four/orkowatch/internal/vulnrecord"
)

// advisory is one line of dnf5 advisory list --json: the advisory and the
// newer package of it that applies to an installed one.
type advisory struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	NEVRA string `json:"nevra"`
}

// liveHost reads what the comparison needs, or skips when it is not there:
// the host, its installed packages, and the records of FEDORA_UPDATEINFO.
func liveHost(t *testing.T) (*osfingerprint.OSInfo, []softwarelist.SoftwareEntry, []vulnrecord.Record) {
	t.Helper()
	file := os.Getenv("FEDORA_UPDATEINFO")
	if _, err := exec.LookPath("dnf5"); file == "" || err != nil {
		t.Skip("FEDORA_UPDATEINFO and dnf5 are needed")
	}
	host, err := osfingerprint.GetOSFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if !(Updates{}).AppliesTo(host) {
		t.Fatalf("the host is %+v, not a Fedora release", host)
	}
	entries, err := softwarelist.GetInstalledSoftwareList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file) // #nosec G304 -- the test's own input
	if err != nil {
		t.Fatal(err)
	}
	var records []vulnrecord.Record
	if _, err := (Updates{}).Records(bytes.NewReader(data), host, func(r vulnrecord.Record) error {
		records = append(records, r)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Logf("%s, %d packages installed, %d security updates", host.Target(), len(entries), len(records))
	return host, entries, records
}

// dnfAdvisories is what dnf5 lists: each security advisory and the name of
// each installed package it has a newer build of.
func dnfAdvisories(t *testing.T) map[string]bool {
	t.Helper()
	out, err := exec.Command("dnf5", "-q", "advisory", "list", "--security", "--json").Output() // #nosec G204 -- fixed arguments
	if err != nil {
		t.Fatalf("dnf5: %v", err)
	}
	var listed []advisory
	if err := json.Unmarshal(out, &listed); err != nil {
		t.Fatalf("dnf5 printed %q: %v", out, err)
	}
	pairs := map[string]bool{}
	for _, a := range listed {
		if a.Type == "security" {
			pairs[a.Name+" "+nameOf(a.NEVRA)] = true
		}
	}
	return pairs
}

// nameOf is the name of a package written as name-[epoch:]version-release.arch.
func nameOf(nevra string) string {
	rest := nevra[:strings.LastIndex(nevra, ".")]
	for range 2 {
		rest = rest[:strings.LastIndex(rest, "-")]
	}
	return rest
}

// owatchAdvisories is what owatch's matching finds of each update alone:
// each advisory and the name of each installed package it affects.
func owatchAdvisories(t *testing.T, entries []softwarelist.SoftwareEntry, records []vulnrecord.Record) map[string]bool {
	t.Helper()
	pairs := map[string]bool{}
	for _, r := range records {
		m, err := vulnmatch.New(softwarelist.ManagerRPM, Updates{}.Combining(), entries, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Add(r); err != nil {
			t.Fatal(err)
		}
		v := m.Result()
		for _, n := range v.NotMatched {
			t.Errorf("%s %s %s was not matched: %s", n.ID, n.Package, n.Installed, n.Reason)
		}
		for _, pkg := range v.Packages {
			pairs[r.ID+" "+pkg.Package] = true
		}
	}
	return pairs
}

// differ lists what one set holds that the other does not, at most a few of
// each, and how many differ in all.
func differ(t *testing.T, what string, dnf, owatch map[string]bool) {
	t.Helper()
	var onlyDnf, onlyOwatch []string
	for k := range dnf {
		if !owatch[k] {
			onlyDnf = append(onlyDnf, k)
		}
	}
	for k := range owatch {
		if !dnf[k] {
			onlyOwatch = append(onlyOwatch, k)
		}
	}
	slices.Sort(onlyDnf)
	slices.Sort(onlyOwatch)
	t.Logf("%s: dnf %d, owatch %d, %d differ", what, len(dnf), len(owatch), len(onlyDnf)+len(onlyOwatch))
	for _, k := range onlyDnf[:min(len(onlyDnf), 20)] {
		t.Errorf("%s: dnf lists %s, owatch does not", what, k)
	}
	for _, k := range onlyOwatch[:min(len(onlyOwatch), 20)] {
		t.Errorf("%s: owatch finds %s, dnf does not list it", what, k)
	}
}

// The advisories dnf lists for the installed packages, each with the
// package it has a newer build of, are those owatch's matching finds of each
// update alone.
func TestFedoraLiveByAdvisory(t *testing.T) {
	_, entries, records := liveHost(t)
	differ(t, "by advisory", dnfAdvisories(t), owatchAdvisories(t, entries, records))
}

// The vulnerabilities owatch reports for each installed package, the whole
// file matched at once as a run matches it, are the CVEs of the advisories
// dnf lists for that package, or the advisory where it names none.
func TestFedoraLiveByCVE(t *testing.T) {
	_, entries, records := liveHost(t)
	byID := map[string]vulnrecord.Record{}
	for _, r := range records {
		byID[r.ID] = r
	}
	dnf := map[string]bool{}
	for pair := range dnfAdvisories(t) {
		id, name, _ := strings.Cut(pair, " ")
		r, ok := byID[id]
		if !ok {
			t.Errorf("dnf lists %s, which the updateinfo does not hold", id)
			continue
		}
		ids := r.CVEs
		if len(ids) == 0 {
			ids = []string{r.ID}
		}
		for _, cve := range ids {
			dnf[cve+" "+name] = true
		}
	}
	m, err := vulnmatch.New(softwarelist.ManagerRPM, Updates{}.Combining(), entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if err := m.Add(r); err != nil {
			t.Fatal(err)
		}
	}
	owatch := map[string]bool{}
	for _, pkg := range m.Result().Packages {
		for _, v := range pkg.Vulnerabilities {
			owatch[v.ID+" "+pkg.Package] = true
		}
	}
	differ(t, "by CVE", dnf, owatch)
}
