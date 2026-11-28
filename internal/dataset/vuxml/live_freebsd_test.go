//go:build freebsd

// internal/dataset/vuxml/live_freebsd_test.go

// The document as pkg audit reads it, set against the matching of owatch, on
// a FreeBSD host with pkg: the same file, the same package versions, and the
// entries each names for them must be the same. It runs where VUXML_FILE
// names a copy of vuln.xml.bz2 and pkg is on the machine, and is skipped
// elsewhere.

package vuxml

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/softwarelist"
	"github.com/papa0four/orkowatch/internal/vulnmatch"
	"github.com/papa0four/orkowatch/internal/vulnrecord"
)

// liveSample bounds how many of the versions the document's bounds name are
// asked of pkg audit, which reads the whole document on each call.
const liveSample = 400

// page is the line pkg audit gives each entry it finds, which names the
// entry by its identifier.
var page = regexp.MustCompile(`WWW: https://vuxml\.FreeBSD\.org/freebsd/([0-9a-f-]{36})\.html`)

// live is what the live comparison reads: pkg, the document's records, and a
// copy of the document expanded for pkg.
type live struct {
	pkg      string
	expanded string
	records  []vulnrecord.Record
	byID     map[string]vulnrecord.Record
}

// liveDocument reads VUXML_FILE, or skips when it or pkg is not there.
func liveDocument(t *testing.T) live {
	t.Helper()
	file := os.Getenv("VUXML_FILE")
	pkg, err := exec.LookPath("pkg")
	if file == "" || err != nil {
		t.Skip("VUXML_FILE and pkg are needed")
	}
	data, err := os.ReadFile(file) // #nosec G304 -- the test's own input
	if err != nil {
		t.Fatal(err)
	}
	var records []vulnrecord.Record
	if _, err := (Document{}).Records(bytes.NewReader(data), freebsd, func(r vulnrecord.Record) error {
		records = append(records, r)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	expanded := filepath.Join(t.TempDir(), "vuln.xml")
	plain, err := io.ReadAll(bzip2.NewReader(bytes.NewReader(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(expanded, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	byID := map[string]vulnrecord.Record{}
	for _, r := range records {
		byID[r.ID] = r
	}
	return live{pkg: pkg, expanded: expanded, records: records, byID: byID}
}

// owatch is what owatch's matching reports affected: each vulnerability, a
// CVE or the identifier of an entry that names none, by package and version.
func (l live) owatch(t *testing.T, entries []softwarelist.SoftwareEntry) map[string][]string {
	t.Helper()
	m, err := vulnmatch.New(softwarelist.ManagerPkg, Document{}.Combining(), entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range l.records {
		if err := m.Add(r); err != nil {
			t.Fatal(err)
		}
	}
	found := map[string][]string{}
	for _, p := range m.Result().Packages {
		key := p.Package + "-" + p.Installed
		for _, v := range p.Vulnerabilities {
			if !slices.Contains(found[key], v.ID) {
				found[key] = append(found[key], v.ID)
			}
		}
		sort.Strings(found[key])
	}
	return found
}

// audit is what pkg audit reports affected for one package version, or for
// every installed package when nameVersion is empty: the vulnerabilities of
// each entry it names, read from the document as owatch reports them, by
// package and version.
func (l live) audit(t *testing.T, nameVersion string) map[string][]string {
	t.Helper()
	args := []string{"audit", "-f", l.expanded}
	if nameVersion != "" {
		args = append(args, nameVersion)
	}
	out, err := exec.Command(l.pkg, args...).CombinedOutput() // #nosec G204 -- the test's own package names
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 {
			t.Fatalf("pkg %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	found := map[string][]string{}
	current := ""
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if pkgVersion, ok := strings.CutSuffix(line, " is vulnerable:"); ok {
			current = pkgVersion
			continue
		}
		if m := page.FindStringSubmatch(line); m != nil && current != "" {
			for _, id := range l.reported(m[1]) {
				if !slices.Contains(found[current], id) {
					found[current] = append(found[current], id)
				}
			}
		}
	}
	for k := range found {
		sort.Strings(found[k])
	}
	return found
}

// reported is what an entry pkg audit names is reported as: its CVEs, or its
// identifier when it names none. An entry the document does not hold, which
// pkg could only name from another file, is reported as its identifier.
func (l live) reported(vid string) []string {
	if r, ok := l.byID[vid]; ok && len(r.CVEs) > 0 {
		return r.CVEs
	}
	return []string{vid}
}

// compare reports each package version the two name different entries for.
func compare(t *testing.T, what string, pkgAudit, owatch map[string][]string) {
	t.Helper()
	keys := map[string]bool{}
	for k := range pkgAudit {
		keys[k] = true
	}
	for k := range owatch {
		keys[k] = true
	}
	differ := 0
	for k := range keys {
		if !slices.Equal(pkgAudit[k], owatch[k]) {
			differ++
			if differ <= 20 {
				t.Errorf("%s: %s: pkg audit names %q, owatch %q", what, k, pkgAudit[k], owatch[k])
			}
		}
	}
	t.Logf("%s: %d package versions affected by pkg audit, %d by owatch, %d differ", what, len(pkgAudit), len(owatch), differ)
}

// sample is the package versions asked of pkg audit: the version of every
// bound of a rarer kind, exactly, up to, or after, and a stride through the
// versions of the rest, from and before, and for each package named, a
// version before any release. A bound whose version holds a * names a series,
// not a version a package can be at, and is not asked.
func (l live) sample() []softwarelist.SoftwareEntry {
	rare, common := l.bounds()
	keys := pick(rare, common)
	var out []softwarelist.SoftwareEntry
	named := map[string]bool{}
	for _, k := range keys {
		name, version, _ := strings.Cut(k, sep)
		out = append(out, softwarelist.SoftwareEntry{Name: name, Version: version, Manager: softwarelist.ManagerPkg})
		if !named[name] {
			named[name] = true
			out = append(out, softwarelist.SoftwareEntry{Name: name, Version: "0.0.0.1", Manager: softwarelist.ManagerPkg})
		}
	}
	return out
}

// sep parts a package's name from a version in the keys of a sample.
const sep = "\t"

// bounds is each package name and version a bound of the document names,
// once, parted into those of the rarer kinds and the rest, sorted. The first
// version, and a version that holds a *, are left out.
func (l live) bounds() (rare, common []string) {
	seen := map[string]bool{}
	l.eachBound(func(name string, b vulnrecord.Bound) {
		key := name + sep + b.Version
		if seen[key] || b.Version == vulnrecord.First || strings.Contains(b.Version, "*") {
			return
		}
		seen[key] = true
		if b.Kind == vulnrecord.Exactly || b.Kind == vulnrecord.UpTo || b.Kind == vulnrecord.After {
			rare = append(rare, key)
		} else {
			common = append(common, key)
		}
	})
	sort.Strings(rare)
	sort.Strings(common)
	return rare, common
}

// eachBound gives do each bound of the document with the name of the package
// it bounds.
func (l live) eachBound(do func(name string, b vulnrecord.Bound)) {
	for _, r := range l.records {
		for _, a := range r.Affected {
			for _, rg := range a.Ranges {
				for _, b := range rg {
					do(a.Package, b)
				}
			}
		}
	}
}

// pick is every rare key and a stride through the common ones, up to
// liveSample in all.
func pick(rare, common []string) []string {
	keys := slices.Clone(rare)
	if room := liveSample - len(keys); room > 0 && len(common) > 0 {
		stride := max(len(common)/room, 1)
		for i := 0; i < len(common) && len(keys) < liveSample; i += stride {
			keys = append(keys, common[i])
		}
	}
	return keys
}

// Every sampled package version is named the same entries by pkg audit and
// by owatch, for the same document.
func TestVuXMLLiveSample(t *testing.T) {
	l := liveDocument(t)
	sample := l.sample()
	pkgAudit := map[string][]string{}
	for _, e := range sample {
		for k, v := range l.audit(t, e.Name+"-"+e.Version) {
			pkgAudit[k] = v
		}
	}
	owatch := map[string][]string{}
	for _, e := range sample {
		for k, v := range l.owatch(t, []softwarelist.SoftwareEntry{e}) {
			owatch[k] = v
		}
	}
	t.Logf("asked %d package versions", len(sample))
	compare(t, "sample", pkgAudit, owatch)
}

// The installed packages are named the same entries by pkg audit and by
// owatch's matching of the inventory owatch reads.
func TestVuXMLLiveInstalled(t *testing.T) {
	l := liveDocument(t)
	installed, err := softwarelist.GetInstalledSoftwareList(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d packages installed", len(installed))
	compare(t, "installed", l.audit(t, ""), l.owatch(t, installed))
}
