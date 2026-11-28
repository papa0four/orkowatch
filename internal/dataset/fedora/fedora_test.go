// internal/dataset/fedora/fedora_test.go

package fedora

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/softwarelist"
	"github.com/papa0four/orkowatch/internal/vulnmatch"
	"github.com/papa0four/orkowatch/internal/vulnrecord"
)

const (
	// excerpt is nine updates of Fedora 44's updateinfo as served on
	// 2026-11-27, each unmodified, with Fedora's license notice before its
	// root, compressed with zstd.
	excerpt    = "testdata/updateinfo-f44-2026-11-27-excerpt.xml.zst"
	excerptSum = "23569431ed8e1f3447af580eb64cff6fb71b6725502c431c4d5bac8d163ad9c1"

	// index is Fedora 44's updates repository's index as served on
	// 2026-11-27, unmodified but for a notice of its terms.
	indexFile = "testdata/repomd-f44-2026-11-27.xml"
	indexSum  = "1cf69f774d24c8f854e63b7f5e76afa6e3d80331142758311ac3140ee1e68b4f"
)

// f44 is a Fedora 44 host, and f42 a host of the archived Fedora 42.
var (
	f44 = &osfingerprint.OSInfo{OS: "linux", Platform: "fedora", PlatformVersion: "44"}
	f42 = &osfingerprint.OSInfo{OS: "linux", Platform: "fedora", PlatformVersion: "42"}
)

// testdata reads the file at path, refusing it unless it is the one its
// checksum names, so the tests read the data as it was taken.
func testdata(t *testing.T, path, sum string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := sha256.Sum256(data)
	if hex.EncodeToString(got[:]) != sum {
		t.Fatalf("%s is not the file taken: its SHA-256 is %x", path, got)
	}
	return data
}

// compressed is document compressed with zstd, as Fedora serves it.
func compressed(t *testing.T, document string) []byte {
	t.Helper()
	var b bytes.Buffer
	z, err := zstd.NewWriter(&b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(z, document); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// keptOf is what Keep keeps for host of fetched, a file as Fedora serves it.
func keptOf(fetched []byte, host *osfingerprint.OSInfo) ([]byte, error) {
	var kept bytes.Buffer
	err := Updates{}.Keep(bytes.NewReader(fetched), int64(len(fetched)), host, &kept)
	return kept.Bytes(), err
}

// mustKeep is keptOf that fails the test when Keep refuses the file.
func mustKeep(t *testing.T, fetched []byte, host *osfingerprint.OSInfo) []byte {
	t.Helper()
	kept, err := keptOf(fetched, host)
	if err != nil {
		t.Fatal(err)
	}
	return kept
}

// records keeps fetched, a file as Fedora serves it, for host and reads what
// was kept, returning what each update gave, by its identifier.
func records(t *testing.T, fetched []byte, host *osfingerprint.OSInfo) (map[string]vulnrecord.Record, dataset.Facts, error) {
	t.Helper()
	kept, err := keptOf(fetched, host)
	if err != nil {
		return nil, dataset.Facts{}, err
	}
	got := map[string]vulnrecord.Record{}
	facts, err := Updates{}.Records(bytes.NewReader(kept), host, func(r vulnrecord.Record) error {
		if _, seen := got[r.ID]; seen {
			t.Errorf("%s was given twice", r.ID)
		}
		got[r.ID] = r
		return nil
	})
	return got, facts, err
}

// The dataset applies to a Fedora host with a release number and no other,
// and states its terms, its limits, its manager, how its updates combine, and
// for each release, the current repository's index, then the archive's, whose
// standing says the release is archived.
func TestUpdatesStatesItself(t *testing.T) {
	u := Updates{}
	for host, applies := range map[*osfingerprint.OSInfo]bool{
		f44: true,
		f42: true,
		{OS: "linux", Platform: "fedora", PlatformVersion: "rawhide"}: false,
		{OS: "linux", Platform: "fedora"}:                             false,
		{OS: "linux", Platform: "fedora", PlatformVersion: "4/4"}:     false,
		{OS: "linux", Platform: "rocky", PlatformVersion: "9"}:        false,
		{OS: "freebsd", Platform: "fedora", PlatformVersion: "44"}:    false,
		nil: false,
	} {
		if u.AppliesTo(host) != applies {
			t.Errorf("%+v: applies %v, want %v", host, !applies, applies)
		}
	}
	if u.ID() != "fedora-updates" || !dataset.ValidID(u.ID()) || u.FetchMaxBytes() != 16<<20 || u.MaxBytes() != 8<<20 || u.Manager() != softwarelist.ManagerRPM || u.Combining() != vulnrecord.AnyRange {
		t.Errorf("states %q, %d, %d, %q, %v", u.ID(), u.FetchMaxBytes(), u.MaxBytes(), u.Manager(), u.Combining())
	}
	var _ dataset.Keeper = u
	if rel, err := u.Release(f44); err != nil || rel != "Fedora 44" {
		t.Errorf("release %q, %v", rel, err)
	}
	if _, err := u.Release(&osfingerprint.OSInfo{OS: "linux", Platform: "rocky", PlatformVersion: "9"}); err == nil {
		t.Error("a release was given for a Rocky Linux host")
	}

	o := u.Origin(f42)
	want := []dataset.Place{
		{URL: "https://dl.fedoraproject.org/pub/fedora/linux/updates/42/Everything/x86_64/repodata/repomd.xml"},
		{URL: "https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/42/Everything/x86_64/repodata/repomd.xml", Standing: "Fedora 42 is archived and receives no updates"},
	}
	if !slices.Equal(o.Places(), want) || o.Index == nil || o.Index.MaxBytes != 64<<10 || o.Index.Locate == nil || o.License != "CC BY-SA 4.0" || !strings.Contains(o.Attribution, "Red Hat, Inc. and others") {
		t.Errorf("origin %+v", o)
	}
	if hosts, err := o.Hosts(); err != nil || !slices.Equal(hosts, []string{"dl.fedoraproject.org"}) {
		t.Errorf("hosts %q, %v", hosts, err)
	}
	if _, err := u.Origin(&osfingerprint.OSInfo{OS: "linux", Platform: "rocky", PlatformVersion: "9"}).Hosts(); err == nil {
		t.Error("a host the dataset does not apply to was given an origin to fetch from")
	}
}

// The repository's index gives the updateinfo's address, resolved against
// the repository's root, with the checksum and size it states.
func TestLocateTheIndex(t *testing.T) {
	at, err := url.Parse("https://dl.fedoraproject.org/pub/fedora/linux/updates/44/Everything/x86_64/repodata/repomd.xml")
	if err != nil {
		t.Fatal(err)
	}
	loc, err := locate(bytes.NewReader(testdata(t, indexFile, indexSum)), at)
	want := dataset.Location{
		URL:    "https://dl.fedoraproject.org/pub/fedora/linux/updates/44/Everything/x86_64/repodata/e28ad27a010e41d29131b62ffb9e5bc006d7bc04fb040fedb252f145534d779a-updateinfo.xml.zst",
		SHA256: "e28ad27a010e41d29131b62ffb9e5bc006d7bc04fb040fedb252f145534d779a",
		Size:   2594654,
	}
	if err != nil || loc != want {
		t.Errorf("located %+v, %v; want %+v", loc, err, want)
	}
}

// An index that is not a repository's, names no updateinfo, or places it
// anywhere but a zstd file of the repository's metadata, or with a checksum
// that is not SHA-256, is refused.
func TestLocateRefuses(t *testing.T) {
	at, err := url.Parse("https://dl.fedoraproject.org/pub/fedora/linux/updates/44/Everything/x86_64/repodata/repomd.xml")
	if err != nil {
		t.Fatal(err)
	}
	entry := func(href, sumType string) string {
		return `<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="updateinfo"><checksum type="` + sumType + `">` +
			strings.Repeat("ab", 32) + `</checksum><location href="` + href + `"/><size>10</size></data></repomd>`
	}
	for name, tt := range map[string]struct{ index, what string }{
		"not XML":             {"not xml", "not a repository's index"},
		"another namespace":   {`<repomd xmlns="urn:other"/>`, "not a repository's index"},
		"another document":    {`<other/>`, "not a repository's index"},
		"no updateinfo":       {`<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary"/></repomd>`, "names no updateinfo"},
		"outside the repo":    {entry("../../elsewhere/updateinfo.xml.zst", "sha256"), "not a zstd file in the repository's metadata"},
		"climbing out":        {entry("repodata/../../x.xml.zst", "sha256"), "not a zstd file in the repository's metadata"},
		"another compression": {entry("repodata/abc-updateinfo.xml.xz", "sha256"), "not a zstd file in the repository's metadata"},
		"an absolute address": {entry("https://elsewhere.example/repodata/x.xml.zst", "sha256"), "not a zstd file in the repository's metadata"},
		"another checksum":    {entry("repodata/abc-updateinfo.xml.zst", "md5"), "not sha256"},
		"an entity":           {`<!DOCTYPE r [<!ENTITY x "y">]><repomd xmlns="http://linux.duke.edu/metadata/repo">&x;</repomd>`, "not a repository's index"},
	} {
		if _, err := locate(strings.NewReader(tt.index), at); err == nil || !strings.Contains(err.Error(), tt.what) {
			t.Errorf("%s: gave %v, want it refused: %s", name, err, tt.what)
		}
	}
}

// wanted is what a record of the excerpt must say: its CVEs, rating, and
// times, how many packages it affects, and one of them with its build.
type wanted struct {
	cves             []string
	rating           string
	published, modif string
	packages         int
	first, fixed     string
}

// check fails the test where r does not say what is wanted of it.
func (want wanted) check(t *testing.T, r vulnrecord.Record) {
	t.Helper()
	if !slices.Equal(r.CVEs, want.cves) || r.Rating != want.rating || r.Published != want.published || r.Modified != want.modif || r.Advisory != "https://bodhi.fedoraproject.org/updates/"+r.ID {
		t.Errorf("%s: %+v", r.ID, r)
	}
	if len(r.Affected) != want.packages {
		t.Errorf("%s affects %d packages, want %d: %+v", r.ID, len(r.Affected), want.packages, r.Affected)
		return
	}
	at := slices.IndexFunc(r.Affected, func(a vulnrecord.Affected) bool { return a.Package == want.first })
	if at < 0 {
		t.Errorf("%s does not affect %s", r.ID, want.first)
		return
	}
	bounds := []vulnrecord.Bound{{Kind: vulnrecord.From, Version: vulnrecord.First}, {Kind: vulnrecord.Before, Version: want.fixed}}
	if a := r.Affected[at]; a.Ecosystem != "Fedora 44" || len(a.Ranges) != 1 || !slices.Equal(a.Ranges[0], bounds) {
		t.Errorf("%s: %s is affected as %+v", r.ID, want.first, a)
	}
}

// The excerpt gives each of its security updates of Fedora 44 as a record:
// its CVEs from its references' titles, each once and in order, or none, its
// severity as the source's rating with None as none stated, its times, its
// page, and each binary package before its build, with the epoch written as
// the inventory writes it and the source package left out. The bugfix and the
// update of Fedora 45 are not given, and the data's date is the latest of
// Fedora 44's updates, bugfix included.
func TestRecordsOfTheExcerpt(t *testing.T) {
	got, facts, err := records(t, testdata(t, excerpt, excerptSum), f44)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 11, 22, 1, 23, 1, 0, time.UTC); !facts.Date.Equal(want) || facts.Version != "Fedora 44" {
		t.Errorf("facts %+v", facts)
	}
	ids := make([]string, 0, len(got))
	for id := range got {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	wantIDs := []string{"FEDORA-2026-09e76d9a09", "FEDORA-2026-1f248487e4", "FEDORA-2026-3bce8d3f11", "FEDORA-2026-490a0000af",
		"FEDORA-2026-9f2b45e4c1", "FEDORA-2026-e5643418cc", "FEDORA-2026-f06a7887af"}
	if !slices.Equal(ids, wantIDs) {
		t.Fatalf("records %q, want %q", ids, wantIDs)
	}

	for id, want := range map[string]wanted{
		"FEDORA-2026-09e76d9a09": {nil, "Moderate", "2026-11-13T16:41:58Z", "2026-11-22T01:23:01Z", 4, "python3-pydantic-settings", "2.15.0-2.fc44"},
		"FEDORA-2026-1f248487e4": {[]string{"CVE-2026-54590", "CVE-2026-54591"}, "Important", "2026-07-11T21:55:14Z", "2026-07-20T00:53:11Z", 1, "python3-asyncssh", "2.24.0-1.fc44"},
		"FEDORA-2026-9f2b45e4c1": {[]string{"CVE-2025-65858", "CVE-2026-25636", "CVE-2026-73248", "CVE-2026-73249"}, "", "2026-08-16T20:29:49Z", "2026-08-25T01:00:59Z", 3, "calibre", "9.13.0-1.fc44"},
		"FEDORA-2026-490a0000af": {[]string{"CVE-2026-119719", "CVE-2026-119718", "CVE-2026-119722"}, "Low", "2026-11-15T04:34:53Z", "2026-11-19T21:13:04Z", 4, "blender", "1:5.2.4-1.fc44"},
		"FEDORA-2026-3bce8d3f11": {[]string{"CVE-2026-48710"}, "Critical", "2026-05-28T19:13:31Z", "2026-06-05T04:25:00Z", 2, "python3-starlette", "0.52.1-2.fc44"},
	} {
		want.check(t, got[id])
	}
	speex := got["FEDORA-2026-e5643418cc"]
	if len(speex.Affected) != 6 || slices.ContainsFunc(speex.Affected, func(a vulnrecord.Affected) bool { return a.Package == "mingw-speex" }) {
		t.Errorf("mingw-speex's update affects %+v, want its six binary packages and not its source", speex.Affected)
	}
	soup := got["FEDORA-2026-f06a7887af"]
	if len(soup.CVEs) != 13 || soup.CVEs[0] != "CVE-2026-3099" || soup.CVEs[12] != "CVE-2026-103399" {
		t.Errorf("libsoup3's update names %q", soup.CVEs)
	}
	names := map[string]int{}
	for _, a := range soup.Affected {
		names[a.Package]++
	}
	for name, n := range names {
		if n != 1 {
			t.Errorf("libsoup3's update affects %s %d times, once for each architecture", name, n)
		}
	}
}

// A package installed before an update's build is affected by its CVEs, with
// the build as the fix; one at the build is not; and one whose epoch is
// higher than the build's is not, whatever its version.
func TestMatchesAsDnfDoes(t *testing.T) {
	data := mustKeep(t, testdata(t, excerpt, excerptSum), f44)
	match := func(name, version string) []string {
		t.Helper()
		m, err := vulnmatch.New(softwarelist.ManagerRPM, Updates{}.Combining(), []softwarelist.SoftwareEntry{{Name: name, Version: version, Manager: softwarelist.ManagerRPM, Architecture: "x86_64"}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := (Updates{}).Records(bytes.NewReader(data), f44, m.Add); err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, pkg := range m.Result().Packages {
			for _, v := range pkg.Vulnerabilities {
				ids = append(ids, v.ID+" fixed in "+v.Fixed)
			}
		}
		slices.Sort(ids)
		return ids
	}
	for _, tt := range []struct {
		name, version string
		want          []string
	}{
		{"python3-asyncssh", "2.23.0-1.fc44", []string{"CVE-2026-54590 fixed in 2.24.0-1.fc44", "CVE-2026-54591 fixed in 2.24.0-1.fc44"}},
		{"python3-asyncssh", "2.24.0-1.fc44", nil},
		{"python3-asyncssh", "2.24.0-2.fc44", nil},
		{"blender", "1:5.2.3-1.fc44", []string{"CVE-2026-119718 fixed in 1:5.2.4-1.fc44", "CVE-2026-119719 fixed in 1:5.2.4-1.fc44", "CVE-2026-119722 fixed in 1:5.2.4-1.fc44"}},
		{"blender", "5.2.9-1.fc44", []string{"CVE-2026-119718 fixed in 1:5.2.4-1.fc44", "CVE-2026-119719 fixed in 1:5.2.4-1.fc44", "CVE-2026-119722 fixed in 1:5.2.4-1.fc44"}},
		{"blender", "2:4.0-1.fc44", nil},
		{"python3-pydantic-settings", "2.14.0-1.fc44", []string{"FEDORA-2026-09e76d9a09 fixed in 2.15.0-2.fc44"}},
		{"python3-truststore", "0.10.0-1.fc44", nil},
	} {
		if got := match(tt.name, tt.version); !slices.Equal(got, tt.want) {
			t.Errorf("%s %s: %q, want %q", tt.name, tt.version, got, tt.want)
		}
	}
}

// update is a security update of release written as updateinfo writes one,
// shipping its packages, for the refusals.
func updateOf(release, packages string) string {
	return `<update from="updates@fedoraproject.org" status="stable" type="security" version="2.0"><id>FEDORA-2026-0123456789</id>` +
		`<issued date="2026-11-13 14:42:02"/><updated date="2026-11-22 01:23:01"/><release>` + release + `</release><severity>Low</severity>` +
		`<references><reference href="https://bugzilla.redhat.com/show_bug.cgi?id=1" id="1" type="bugzilla" title="CVE-2026-1234 x"/></references>` +
		`<pkglist><collection short="F44"><name>Fedora 44</name>` + packages + `</collection></pkglist></update>`
}

// pkg is a package element of an update.
const pkg = `<package name="speex" version="1.2.1" release="4.fc44" epoch="0" arch="x86_64" src="x"><filename>x</filename></package>`

// A file that is not updateinfo, is cut short, holds no security update of
// the host's release, holds an entity, or holds a security update of the
// release that is not in updateinfo's form is refused when it is kept,
// naming why; so is a host the dataset is not for.
func TestRefuses(t *testing.T) {
	whole := func(updates string) string { return `<?xml version="1.0"?><updates>` + updates + `</updates>` }
	cases := map[string]struct {
		data []byte
		what string
	}{
		"not zstd":                 {[]byte("<updates/>"), "magic"},
		"another document":         {compressed(t, `<vuxml/>`), "not Fedora's updateinfo"},
		"cut short":                {compressed(t, whole(updateOf("Fedora 44", pkg)))[:40], ""},
		"no update of the release": {compressed(t, whole(updateOf("Fedora 45", pkg))), "holds no security update of Fedora 44"},
		"no security update": {compressed(t, whole(strings.Replace(updateOf("Fedora 44", pkg), `type="security"`, `type="bugfix"`, 1))),
			"holds no security update of Fedora 44"},
		"no update at all":     {compressed(t, whole("")), "holds no security update of Fedora 44"},
		"another element":      {compressed(t, whole(`<advisory/>`)), "advisory is not an update"},
		"text between updates": {compressed(t, whole(updateOf("Fedora 44", pkg)+"stray")), "text between its updates"},
		"after the end":        {compressed(t, whole(updateOf("Fedora 44", pkg))+"<updates/>"), "an element after its end"},
		"an entity":            {compressed(t, `<!DOCTYPE u [<!ENTITY x "y">]><updates>&x;</updates>`), "invalid character entity"},
		"a bad identifier": {compressed(t, whole(strings.Replace(updateOf("Fedora 44", pkg), "FEDORA-2026-0123456789", "FEDORA-EPEL-2026-1", 1))),
			"its identifier is not an update's"},
		"no time issued": {compressed(t, whole(strings.Replace(updateOf("Fedora 44", pkg), `<issued date="2026-11-13 14:42:02"/>`, "", 1))),
			"gives no time it was issued"},
		"a time not a time": {compressed(t, whole(strings.Replace(updateOf("Fedora 44", pkg), "2026-11-22 01:23:01", "yesterday", 1))),
			`"yesterday" is not a time`},
		"no binary package": {compressed(t, whole(updateOf("Fedora 44", strings.Replace(pkg, `arch="x86_64"`, `arch="src"`, 1)))),
			"ships no binary package"},
		"an epoch not a number": {compressed(t, whole(updateOf("Fedora 44", strings.Replace(pkg, `epoch="0"`, `epoch="one"`, 1)))),
			`gives the epoch "one"`},
		"a name with an escape": {compressed(t, whole(updateOf("Fedora 44", strings.Replace(pkg, `name="speex"`, `name="speex&#x9b;2J"`, 1)))),
			"holds a control character"},
		"a version too long": {compressed(t, whole(updateOf("Fedora 44", strings.Replace(pkg, `version="1.2.1"`, `version="`+strings.Repeat("1", dataset.MaxText+1)+`"`, 1)))),
			"longer than"},
	}
	for name, tt := range cases {
		if _, _, err := records(t, tt.data, f44); err == nil || !strings.Contains(err.Error(), tt.what) {
			t.Errorf("%s: gave %v, want it refused: %s", name, err, tt.what)
		}
	}
	if _, _, err := records(t, compressed(t, whole(updateOf("Fedora 44", pkg))), f44); err != nil {
		t.Errorf("the update the refusals are made from was refused: %v", err)
	}
	rocky := &osfingerprint.OSInfo{OS: "linux", Platform: "rocky", PlatformVersion: "9"}
	if _, err := keptOf(testdata(t, excerpt, excerptSum), rocky); err == nil {
		t.Error("the updateinfo was kept for a Rocky Linux host")
	}
	if _, err := (Updates{}).Check(bytes.NewReader(mustKeep(t, testdata(t, excerpt, excerptSum), f44)), rocky); err == nil {
		t.Error("what was kept was checked for a Rocky Linux host")
	}
}

// What is kept is the release's security updates, each element as the file
// holds it, inside an updates element, compressed with gzip, and nothing of
// another release or that is not a security update.
func TestKeepsTheReleasesSecurityUpdates(t *testing.T) {
	kept := mustKeep(t, testdata(t, excerpt, excerptSum), f44)
	gz, err := gzip.NewReader(bytes.NewReader(kept))
	if err != nil {
		t.Fatal(err)
	}
	text, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := zstd.NewReader(bytes.NewReader(testdata(t, excerpt, excerptSum)))
	if err != nil {
		t.Fatal(err)
	}
	defer expanded.Close()
	original, err := io.ReadAll(expanded)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(text), keptHead) || !strings.HasSuffix(string(text), keptTail) {
		t.Errorf("kept %.80q ... %q", text, text[max(0, len(text)-40):])
	}
	updates := regexp.MustCompile(`(?s)<update .*?</update>`).FindAllString(string(text), -1)
	if len(updates) != 7 {
		t.Fatalf("kept %d updates, want the seven security updates", len(updates))
	}
	for _, u := range updates {
		if !bytes.Contains(original, []byte(u)) || !strings.HasPrefix(u, "<update ") || !strings.HasSuffix(u, "</update>") || !strings.Contains(u, `type="security"`) {
			t.Errorf("kept %.80q, which is not a security update of the file as it holds it", u)
		}
	}
	if strings.Contains(string(text), "FEDORA-2026-3b692ba186") || strings.Contains(string(text), "FEDORA-2026-47312bda9b") {
		t.Error("kept the bugfix or the update of Fedora 45")
	}
}

// What was kept is refused when it is not gzip, holds an update of another
// release or one that is not a security update, or anything after its end:
// none of these is what Keep writes for the host.
func TestRefusesWhatWasNotKeptForTheHost(t *testing.T) {
	gzipped := func(document string) []byte {
		var b bytes.Buffer
		z := gzip.NewWriter(&b)
		if _, err := io.WriteString(z, document); err != nil {
			t.Fatal(err)
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	kept := mustKeep(t, testdata(t, excerpt, excerptSum), f44)
	for name, tt := range map[string]struct {
		data []byte
		host *osfingerprint.OSInfo
		what string
	}{
		"the file Fedora serves":   {testdata(t, excerpt, excerptSum), f44, "not the updates kept"},
		"kept for another release": {kept, f42, "it is an update of Fedora 44, not Fedora 42"},
		"a bugfix": {gzipped(keptHead + strings.Replace(updateOf("Fedora 44", pkg), `type="security"`, `type="bugfix"`, 1) + keptTail), f44,
			"it is a bugfix update, not a security update"},
		"after its end":       {gzipped(keptHead + updateOf("Fedora 44", pkg) + keptTail + "<updates/>"), f44, "an element after its end"},
		"data after the gzip": {append(slices.Clone(kept), "trailing"...), f44, "data follows the updates kept"},
		"a second member":     {append(slices.Clone(kept), gzipped(keptHead+keptTail)...), f44, "data follows the updates kept"},
	} {
		if _, err := (Updates{}).Check(bytes.NewReader(tt.data), tt.host); err == nil || !strings.Contains(err.Error(), tt.what) {
			t.Errorf("%s: gave %v, want it refused: %s", name, err, tt.what)
		}
	}
}

// A file that expands past what it may is refused as that, both the file
// Fedora serves and what was kept, however small each is compressed.
func TestExpandsPastTheLimit(t *testing.T) {
	padded := func(limit int) string {
		return keptHead + strings.Repeat(" ", limit) + updateOf("Fedora 44", pkg) + keptTail
	}
	if _, err := keptOf(compressed(t, padded(maxExpanded)), f44); err == nil || !strings.Contains(err.Error(), "expands past") {
		t.Errorf("a file Fedora serves past the limit gave %v", err)
	}
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	if _, err := io.WriteString(z, padded(maxKeptExpanded)); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := (Updates{}).Check(&b, f44); err == nil || !strings.Contains(err.Error(), "the updates kept expand past") {
		t.Errorf("what was kept past the limit gave %v", err)
	}
}

// securityUpdate is a security update written as updateinfo writes one, with its own
// identifier, times, CVE, and the build of speex it ships.
func securityUpdate(ident, issued, updated, cve, version string) string {
	u := updateOf("Fedora 44", strings.Replace(pkg, `version="1.2.1"`, `version="`+version+`"`, 1))
	u = strings.Replace(u, "FEDORA-2026-0123456789", ident, 1)
	u = strings.Replace(u, "2026-11-13 14:42:02", issued, 1)
	u = strings.Replace(u, "2026-11-22 01:23:01", updated, 1)
	return strings.Replace(u, "CVE-2026-1234", cve, 1)
}

// The data's date is the latest time any security update of the release
// gives, wherever in the file it is, and an update's own latest time is the later
// of when it was issued and updated.
func TestTheDataIsDatedByItsLatestUpdate(t *testing.T) {
	document := `<updates>` +
		securityUpdate("FEDORA-2026-000000000a", "2026-01-02 03:04:05", "2026-01-03 03:04:05", "CVE-2026-1001", "1.0") +
		securityUpdate("FEDORA-2026-000000000b", "2026-06-01 00:00:00", "2026-05-01 00:00:00", "CVE-2026-1002", "1.1") +
		`</updates>`
	_, facts, err := records(t, compressed(t, document), f44)
	if want := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC); err != nil || !facts.Date.Equal(want) {
		t.Errorf("dated %v, %v; want %v", facts.Date, err, want)
	}
}

// A CVE two updates of one package name, the later shipping a later build,
// is affected at a version between them, as dnf lists the later update for
// it: the earlier fix does not clear what the later update still names.
func TestALaterUpdateOfTheSameCVE(t *testing.T) {
	document := `<updates>` +
		securityUpdate("FEDORA-2026-000000000a", "2026-01-02 03:04:05", "2026-01-03 03:04:05", "CVE-2026-1001", "1.0") +
		securityUpdate("FEDORA-2026-000000000b", "2026-06-01 00:00:00", "2026-06-02 00:00:00", "CVE-2026-1001", "2.0") +
		`</updates>`
	m, err := vulnmatch.New(softwarelist.ManagerRPM, Updates{}.Combining(), []softwarelist.SoftwareEntry{{Name: "speex", Version: "1.5-4.fc44", Manager: softwarelist.ManagerRPM}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Updates{}).Records(bytes.NewReader(mustKeep(t, compressed(t, document), f44)), f44, m.Add); err != nil {
		t.Fatal(err)
	}
	v := m.Result()
	if len(v.Packages) != 1 || len(v.Packages[0].Vulnerabilities) != 1 || v.Packages[0].Vulnerabilities[0].ID != "CVE-2026-1001" || v.Packages[0].Vulnerabilities[0].Fixed != "2.0-4.fc44" {
		t.Errorf("matched %+v, want CVE-2026-1001 fixed in 2.0-4.fc44", v.Packages)
	}
}

// Records stops at the first error what it gives records to returns, and
// returns that error as it is.
func TestRecordsEndAtAnError(t *testing.T) {
	stop := errors.New("stop")
	given := 0
	_, err := Updates{}.Records(bytes.NewReader(mustKeep(t, testdata(t, excerpt, excerptSum), f44)), f44, func(vulnrecord.Record) error {
		given++
		return stop
	})
	if !errors.Is(err, stop) || given != 1 {
		t.Errorf("gave %v after %d records", err, given)
	}
}
