// internal/dataset/osv/osv_test.go

package osv

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/vulnrecord"
)

// The recorded dumps are excerpts, not the dumps as published. Each is records
// copied unchanged from the distribution's dump in OSV's bucket on 2026-11-24:
// the first 25 under 16 KiB that affect the release named, the first 5 under
// 16 KiB that affect only other releases, the first withdrawn record under 16
// KiB, and the records named, in the dump's order, written into a new zip.
var recordings = []struct {
	id, file, sum string
	host          osfingerprint.OSInfo
	release       string
	kept          int
	named         []string
}{
	{"osv-alpine", "testdata/alpine-2026-11-24-excerpt.zip",
		"04d845d6f9ba2419575ee867337ad90164ee70a03a5fc02dcb64cb46cd821655",
		osfingerprint.OSInfo{OS: "linux", Platform: "alpine", PlatformVersion: "3.20.10"}, "Alpine:v3.20", 26,
		[]string{"ALPINE-CVE-2018-12126"}},
	{"osv-almalinux", "testdata/almalinux-2026-11-24-excerpt.zip",
		"dab0def15c25aba0a4daf0ae2f71d2c6fccff877fce5518c2d416203a3376f66",
		osfingerprint.OSInfo{OS: "linux", Platform: "almalinux", PlatformVersion: "9.9"}, "AlmaLinux:9", 25, nil},
	{"osv-rocky", "testdata/rocky-2026-11-24-excerpt.zip",
		"204f9b6109d2b8d960a9bc2011414c1da73eb0ae0be1b93036afff169b2d6317",
		osfingerprint.OSInfo{OS: "linux", Platform: "rocky", PlatformVersion: "9.9"}, "Rocky Linux:9", 25, nil},
	{"osv-redhat", "testdata/redhat-2026-11-24-excerpt.zip",
		"dd5b6e6ba3af9996ebaaf73529db3a77fad18bc40f8f7403274b9622bcf2d3e6",
		osfingerprint.OSInfo{OS: "linux", Platform: "redhat", PlatformVersion: "9.9"}, "Red Hat:enterprise_linux:9", 25,
		[]string{"RHSA-2026:100482", "RHSA-2026:100486", "RHSA-2026:100547"}},
	{"osv-ubuntu", "testdata/ubuntu-2026-11-24-excerpt.zip",
		"58cb94773832a5e0ec6ffcd00d603c58ddd69b1499b1573576881eae9de14e87",
		osfingerprint.OSInfo{OS: "linux", Platform: "ubuntu", PlatformVersion: "22.04"}, "Ubuntu:22.04", 26,
		[]string{"UBUNTU-CVE-2025-46336"}},
}

// dump returns the dataset named id.
func dump(t *testing.T, id string) Dump {
	t.Helper()
	for _, d := range Datasets() {
		if d.ID() == id {
			return d
		}
	}
	t.Fatalf("no dataset %s", id)
	return Dump{}
}

// recorded returns the recorded excerpt at file, having checked it is the one
// recorded.
func recorded(t *testing.T, file, sum string) []byte {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(data); hex.EncodeToString(got[:]) != sum {
		t.Fatalf("%s hashes to %x, not what was recorded", file, got)
	}
	return data
}

// keep keeps from dumped for host and returns what was kept.
func keep(t *testing.T, d Dump, dumped []byte, host *osfingerprint.OSInfo) ([]byte, error) {
	t.Helper()
	var out bytes.Buffer
	err := d.Keep(bytes.NewReader(dumped), int64(len(dumped)), host, &out)
	return out.Bytes(), err
}

// keptIDs lists the identifiers of the records kept data holds.
func keptIDs(t *testing.T, kept []byte) []string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(kept))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	dec := json.NewDecoder(gz)
	for dec.More() {
		var line keptLine
		if err := dec.Decode(&line); err != nil {
			t.Fatal(err)
		}
		if line.ID != "" {
			ids = append(ids, line.ID)
		}
	}
	return ids
}

// The five distributions are named in order, each fetched from its own
// directory of OSV's bucket under the license OSV states for it, with room
// for its dump as measured on 2026-11-24.
func TestDatasets(t *testing.T) {
	measured := map[string]int64{
		"osv-almalinux": 7_510_140, "osv-alpine": 9_358_767, "osv-redhat": 29_832_553,
		"osv-rocky": 6_138_920, "osv-ubuntu": 845_016_925,
	}
	var ids []string
	for _, d := range Datasets() {
		ids = append(ids, d.ID())
		if !dataset.ValidID(d.ID()) || d.FetchMaxBytes() < 4*measured[d.ID()] || d.MaxBytes() <= 0 {
			t.Errorf("%s: id %q may fetch %d and keep %d bytes", d.ID(), d.ID(), d.FetchMaxBytes(), d.MaxBytes())
		}
		if hosts, err := d.Origin(nil).Hosts(); err != nil || len(hosts) != 1 || hosts[0] != "storage.googleapis.com" {
			t.Errorf("%s: hosts %q, %v", d.ID(), hosts, err)
		}
	}
	if want := []string{"osv-almalinux", "osv-alpine", "osv-redhat", "osv-rocky", "osv-ubuntu"}; !slices.Equal(ids, want) {
		t.Errorf("datasets %q, want %q", ids, want)
	}
	// Each names the packages of its distribution's manager, as read on a
	// host of each.
	for id, want := range map[string]string{
		"osv-almalinux": "rpm", "osv-alpine": "apk", "osv-redhat": "rpm", "osv-rocky": "rpm", "osv-ubuntu": "dpkg",
	} {
		if got := dump(t, id).Manager(); got != want {
			t.Errorf("%s: manager %q, want %q", id, got, want)
		}
	}
	for id, want := range map[string][2]string{
		"osv-almalinux": {"https://storage.googleapis.com/osv-vulnerabilities/AlmaLinux/all.zip", "MIT"},
		"osv-alpine":    {"https://storage.googleapis.com/osv-vulnerabilities/Alpine/all.zip", "CC-BY-SA 4.0"},
		"osv-redhat":    {"https://storage.googleapis.com/osv-vulnerabilities/Red%20Hat/all.zip", "CC-BY 4.0"},
		"osv-rocky":     {"https://storage.googleapis.com/osv-vulnerabilities/Rocky%20Linux/all.zip", "BSD"},
		"osv-ubuntu":    {"https://storage.googleapis.com/osv-vulnerabilities/Ubuntu/all.zip", "CC-BY-SA 4.0"},
	} {
		if o := dump(t, id).Origin(nil); o.URL != want[0] || o.License != want[1] || o.Attribution == "" {
			t.Errorf("%s: origin %+v", id, o)
		}
	}
}

// A dataset applies to a Linux host of its distribution, as the fingerprint
// names it, and to no other.
func TestAppliesTo(t *testing.T) {
	d := dump(t, "osv-rocky")
	for _, tt := range []struct {
		host osfingerprint.OSInfo
		want bool
	}{
		{osfingerprint.OSInfo{OS: "linux", Platform: "rocky", PlatformVersion: "9.9"}, true},
		{osfingerprint.OSInfo{OS: "linux", Platform: "almalinux", PlatformVersion: "9.9"}, false},
		{osfingerprint.OSInfo{OS: "freebsd", Platform: "rocky"}, false},
	} {
		if got := d.AppliesTo(&tt.host); got != tt.want {
			t.Errorf("%+v: applies %v, want %v", tt.host, got, tt.want)
		}
	}
	if d.AppliesTo(nil) {
		t.Error("applies to no host")
	}
}

// Each distribution's release is named from the version its hosts report,
// as read on a host of each, and takes the ecosystems of that release alone.
func TestRelease(t *testing.T) {
	for _, tt := range []struct {
		release      func(string) (release, error)
		version      string
		name         string
		accepts, not []string
	}{
		{ubuntu, "22.04", "Ubuntu:22.04", []string{"Ubuntu:22.04:LTS", "Ubuntu:22.04"},
			[]string{"Ubuntu:Pro:22.04:LTS", "Ubuntu:Pro:FIPS:22.04:LTS", "Ubuntu:22.04:LTS:for:NVIDIA:BlueField", "Ubuntu:24.04:LTS"}},
		{ubuntu, "25.10", "Ubuntu:25.10", []string{"Ubuntu:25.10"}, []string{"Ubuntu:Pro:25.10"}},
		{alpine, "3.20.10", "Alpine:v3.20", []string{"Alpine:v3.20"}, []string{"Alpine:v3.2", "Alpine:v3.21"}},
		{alpine, "3.20", "Alpine:v3.20", []string{"Alpine:v3.20"}, nil},
		{major("AlmaLinux"), "9.9", "AlmaLinux:9", []string{"AlmaLinux:9"}, []string{"AlmaLinux:8", "AlmaLinux:10"}},
		{major("Rocky Linux"), "9.9", "Rocky Linux:9", []string{"Rocky Linux:9"}, []string{"Rocky Linux:8"}},
		{redHat, "9.9", "Red Hat:enterprise_linux:9",
			[]string{"Red Hat:enterprise_linux:9::appstream", "Red Hat:enterprise_linux:9::baseos", "Red Hat:enterprise_linux:9::crb"},
			[]string{"Red Hat:rhel_eus:9.4::appstream", "Red Hat:enterprise_linux:8::appstream", "Red Hat:enterprise_linux:90::baseos"}},
		{redHat, "10.3", "Red Hat:enterprise_linux:10.3",
			[]string{"Red Hat:enterprise_linux:10.3", "Red Hat:enterprise_linux:10::fastdatapath"},
			[]string{"Red Hat:enterprise_linux:10.2", "Red Hat:enterprise_linux_eus:10.2", "Red Hat:enterprise_linux:10.30"}},
	} {
		rel, err := tt.release(tt.version)
		if err != nil || rel.name != tt.name {
			t.Errorf("%s: release %q, %v, want %q", tt.version, rel.name, err, tt.name)
			continue
		}
		for _, eco := range tt.accepts {
			if !rel.accepts(eco) {
				t.Errorf("%s: %s is not taken", tt.name, eco)
			}
		}
		for _, eco := range tt.not {
			if rel.accepts(eco) {
				t.Errorf("%s: %s is taken", tt.name, eco)
			}
		}
	}
	for name, try := range map[string]func() (release, error){
		"Ubuntu with a point release": func() (release, error) { return ubuntu("22.04.5") },
		"Ubuntu by name":              func() (release, error) { return ubuntu("jammy") },
		"Alpine with no minor":        func() (release, error) { return alpine("3") },
		"Alpine edge":                 func() (release, error) { return alpine("edge") },
		"Red Hat with no minor":       func() (release, error) { return redHat("9") },
		"an empty version":            func() (release, error) { return major("AlmaLinux")("") },
		"a version with a slash":      func() (release, error) { return major("AlmaLinux")("9/9") },
	} {
		if _, err := try(); err == nil || !strings.Contains(err.Error(), "names no release") {
			t.Errorf("%s: gave %v, want it refused", name, err)
		}
	}
}

// Each recorded excerpt keeps the records of its release, and no withdrawn
// one, and what is kept passes the check for that release and is refused for
// another.
func TestKeepRecordedExcerpts(t *testing.T) {
	for _, r := range recordings {
		t.Run(r.id, func(t *testing.T) {
			d := dump(t, r.id)
			host := r.host
			kept, err := keep(t, d, recorded(t, r.file, r.sum), &host)
			if err != nil {
				t.Fatalf("the excerpt was refused: %v", err)
			}
			ids := keptIDs(t, kept)
			if len(ids) != r.kept {
				t.Errorf("kept %d records, want %d", len(ids), r.kept)
			}
			// Red Hat's named records are of release 10.3, and are kept for
			// it alone.
			if r.id != "osv-redhat" {
				for _, id := range r.named {
					if !slices.Contains(ids, id) {
						t.Errorf("%s was not kept", id)
					}
				}
			}
			checkKept(t, d, kept, host, r.release)
		})
	}
}

// checkKept judges kept data for host, which it must pass naming release, and
// for another release of the same distribution, which it must not.
func checkKept(t *testing.T, d Dump, kept []byte, host osfingerprint.OSInfo, release string) {
	t.Helper()
	facts, err := d.Check(bytes.NewReader(kept), &host)
	if err != nil || facts.Version != release || facts.Date.IsZero() {
		t.Errorf("check gave %+v, %v", facts, err)
	}
	other := host
	other.PlatformVersion = "8.1"
	if host.Platform == "ubuntu" {
		other.PlatformVersion = "24.04"
	}
	if _, err := d.Check(bytes.NewReader(kept), &other); err == nil || !strings.Contains(err.Error(), "not this host's release") {
		t.Errorf("another release gave %v, want it refused", err)
	}
}

// Red Hat 10.3 keeps the records of its minor release from the same dump,
// and none of 9's.
func TestKeepRedHatByMinorRelease(t *testing.T) {
	r := recordings[3]
	host := osfingerprint.OSInfo{OS: "linux", Platform: "redhat", PlatformVersion: "10.3"}
	kept, err := keep(t, dump(t, r.id), recorded(t, r.file, r.sum), &host)
	if err != nil {
		t.Fatal(err)
	}
	if ids := keptIDs(t, kept); !slices.Equal(ids, r.named) {
		t.Errorf("kept %q, want %q", ids, r.named)
	}
}

// A withdrawn record is left out, and a score with no type is left out of a
// record that is kept, with the record's other scores.
func TestKeepLeavesOut(t *testing.T) {
	r := recordings[4]
	host := r.host
	kept, err := keep(t, dump(t, r.id), recorded(t, r.file, r.sum), &host)
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(kept))
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(gz)
	found := false
	for dec.More() {
		var line keptLine
		if err := dec.Decode(&line); err != nil {
			t.Fatal(err)
		}
		if line.ID != "UBUNTU-CVE-2025-46336" {
			continue
		}
		found = true
		if len(line.Severity) != 1 || line.Severity[0].Type != "CVSS_V3" {
			t.Errorf("scores %+v, want the CVSS score alone", line.Severity)
		}
	}
	if !found {
		t.Error("the record with an untyped score was not kept")
	}
}

// rec is a record of Alpine 3.20 in OSV's form, changed by edit.
func rec(id string, edit func(map[string]any)) []byte {
	r := map[string]any{
		"id": id, "modified": "2026-11-23T10:00:00Z", "published": "2026-11-01T10:00:00Z",
		"upstream": []string{"CVE-2026-1234"},
		"severity": []map[string]string{{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
		"affected": []map[string]any{{
			"package": map[string]string{"name": "openssl", "ecosystem": "Alpine:v3.20"},
			"ranges":  []map[string]any{{"type": "ECOSYSTEM", "events": []map[string]string{{"introduced": "0"}, {"fixed": "3.3.2-r0"}}}},
		}},
		"references": []map[string]string{{"type": "ADVISORY", "url": "https://security.alpinelinux.org/vuln/CVE-2026-1234"}},
	}
	if edit != nil {
		edit(r)
	}
	data, err := json.Marshal(r)
	if err != nil {
		panic(err)
	}
	return data
}

// zipped writes entries, name and content in order, as a zip.
func zipped(t *testing.T, entries ...[2][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		f, err := w.Create(string(e[0]))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(e[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// entry is a zip entry named name holding content.
func entry(name string, content []byte) [2][]byte { return [2][]byte{[]byte(name), content} }

// range sets the events of a record's one range.
func withEvents(events ...map[string]string) func(map[string]any) {
	return func(r map[string]any) {
		r["affected"].([]map[string]any)[0]["ranges"] = []map[string]any{{"type": "ECOSYSTEM", "events": events}}
	}
}

// A dump that is not a zip, is cut short, holds an entry that is not one
// record, or holds a record of the release not in the schema's form, is
// refused, naming the record; one with no record of the release is refused,
// naming the releases it holds. A record of another release is not judged.
func TestKeepRefuses(t *testing.T) {
	alpine := &osfingerprint.OSInfo{OS: "linux", Platform: "alpine", PlatformVersion: "3.20.10"}
	good := entry("ALPINE-CVE-2026-1234.json", rec("ALPINE-CVE-2026-1234", nil))
	whole := zipped(t, good)
	elsewhere := func(r map[string]any) {
		r["affected"].([]map[string]any)[0]["package"] = map[string]string{"name": "openssl", "ecosystem": "Alpine:v3.19"}
	}

	if _, err := keep(t, dump(t, "osv-alpine"), whole, alpine); err != nil {
		t.Fatalf("a sound dump was refused: %v", err)
	}
	for name, tt := range map[string]struct {
		data   []byte
		reason string
	}{
		"not a zip":        {[]byte("not a zip"), "not a zip"},
		"cut short":        {whole[:len(whole)-10], "not a zip"},
		"not JSON":         {zipped(t, entry("x.json", []byte("{not json"))), "not an OSV record"},
		"two records":      {zipped(t, entry("x.json", append(rec("A-1", nil), rec("A-2", nil)...))), "text after its record"},
		"a stray brace":    {zipped(t, entry("x.json", append(rec("A-1", nil), '}'))), "text after its record"},
		"a malformed CVE":  {zipped(t, entry("x.json", rec("A-1", func(r map[string]any) { r["upstream"] = []string{"CVE-26-1"} }))), "record A-1: \"CVE-26-1\" is not a CVE"},
		"no introduced":    {zipped(t, entry("x.json", rec("A-1", withEvents(map[string]string{"fixed": "1.0-r0"})))), "no introduced event"},
		"fixed and last":   {zipped(t, entry("x.json", rec("A-1", withEvents(map[string]string{"introduced": "0"}, map[string]string{"fixed": "1"}, map[string]string{"last_affected": "2"})))), "both fixed and last affected"},
		"an unknown event": {zipped(t, entry("x.json", rec("A-1", withEvents(map[string]string{"introduced": "0"}, map[string]string{"patched": "1"})))), "not an event"},
		"two versions":     {zipped(t, entry("x.json", rec("A-1", withEvents(map[string]string{"introduced": "0", "fixed": "1"})))), "names 2 versions"},
		"an empty version": {zipped(t, entry("x.json", rec("A-1", withEvents(map[string]string{"introduced": ""})))), "a version is empty"},
		"a SEMVER range": {zipped(t, entry("x.json", rec("A-1", func(r map[string]any) {
			r["affected"].([]map[string]any)[0]["ranges"].([]map[string]any)[0]["type"] = "SEMVER"
		}))), "of type \"SEMVER\""},
		"no package name": {zipped(t, entry("x.json", rec("A-1", func(r map[string]any) {
			r["affected"].([]map[string]any)[0]["package"] = map[string]string{"ecosystem": "Alpine:v3.20"}
		}))), "a package's name is empty"},
		"a bad identifier": {zipped(t, entry("x.json", rec("../A-1", nil))), "not a record's identifier"},
		"no modified time": {zipped(t, entry("x.json", rec("A-1", func(r map[string]any) { delete(r, "modified") }))), "not an RFC 3339 time"},
		"a plain advisory": {zipped(t, entry("x.json", rec("A-1", func(r map[string]any) {
			r["references"] = []map[string]string{{"type": "ADVISORY", "url": "http://a.example/1"}}
		}))), "not an HTTPS address"},
		"an escape": {zipped(t, entry("x.json", rec("A-1", func(r map[string]any) {
			r["affected"].([]map[string]any)[0]["package"] = map[string]string{"name": "ssl\x1b[2J", "ecosystem": "Alpine:v3.20"}
		}))), "control character"},
		"no release record": {zipped(t, entry("x.json", rec("A-1", elsewhere))), "holds no record of Alpine:v3.20; it holds Alpine:v3.19"},
		"a directory":       {zipped(t, entry("records/", nil)), "not a file"},
	} {
		if _, err := keep(t, dump(t, "osv-alpine"), tt.data, alpine); err == nil || !strings.Contains(err.Error(), tt.reason) {
			t.Errorf("%s: gave %v, want it refused naming %q", name, err, tt.reason)
		}
	}

	// A malformed record of another release is not this host's to judge.
	other := zipped(t, good, entry("y.json", rec("A-2", func(r map[string]any) { elsewhere(r); r["upstream"] = []string{"CVE-26-1"} })))
	if _, err := keep(t, dump(t, "osv-alpine"), other, alpine); err != nil {
		t.Errorf("a malformed record of another release refused the dump: %v", err)
	}
	// Nothing is kept for a host of another distribution.
	if _, err := keep(t, dump(t, "osv-alpine"), whole, &osfingerprint.OSInfo{OS: "linux", Platform: "ubuntu", PlatformVersion: "22.04"}); err == nil {
		t.Error("an Ubuntu host kept Alpine's records")
	}
}

// An entry that expands past what is left of the dump's room, or past what a
// record may hold, is refused.
func TestReadEntryBounds(t *testing.T) {
	big := rec("A-1", func(r map[string]any) { r["details"] = strings.Repeat("x", 4<<10) })
	archive, err := zip.NewReader(bytes.NewReader(zipped(t, entry("x.json", big))), int64(len(zipped(t, entry("x.json", big)))))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := readEntry(archive.File[0], 1<<10); err == nil || !strings.Contains(err.Error(), "expands past the 1024 bytes") {
		t.Errorf("an entry past the room left gave %v", err)
	}
	if _, n, err := readEntry(archive.File[0], 1<<20); err != nil || n != int64(len(big)) {
		t.Errorf("an entry within the room gave %d bytes, %v", n, err)
	}
}

// kept returns kept data for Alpine 3.20 written from lines, each a JSON
// value.
func keptData(t *testing.T, lines ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	for _, l := range lines {
		if _, err := gz.Write([]byte(l + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Kept data is refused unless every line is in the form Keep writes: a
// header of this format for the host's release, records of that release, and
// a trailer that counts them, with nothing after it.
func TestCheckRefuses(t *testing.T) {
	alpine := &osfingerprint.OSInfo{OS: "linux", Platform: "alpine", PlatformVersion: "3.20.10"}
	head := `{"format":1,"release":"Alpine:v3.20"}`
	line := `{"id":"A-1","cves":["CVE-2026-1234"],"modified":"2026-11-23T10:00:00Z","affected":[{"package":"openssl","ecosystem":"Alpine:v3.20","ranges":[[{"introduced":"0"},{"fixed":"3.3.2-r0"}]]}]}`
	tail := `{"records":1,"modified":"2026-11-23T10:00:00Z"}`
	d := dump(t, "osv-alpine")

	facts, err := d.Check(bytes.NewReader(keptData(t, head, line, tail)), alpine)
	if err != nil || facts.Version != "Alpine:v3.20" || facts.Date.Format("2006-01-02") != "2026-11-23" {
		t.Fatalf("sound kept data gave %+v, %v", facts, err)
	}
	for name, tt := range map[string]struct {
		lines  []string
		reason string
	}{
		"another format":      {[]string{`{"format":2,"release":"Alpine:v3.20"}`, line, tail}, "format 1"},
		"another release":     {[]string{`{"format":1,"release":"Alpine:v3.19"}`, line, tail}, "not this host's release"},
		"no trailer":          {[]string{head, line}, "end before their trailer"},
		"a count too high":    {[]string{head, line, `{"records":2,"modified":"2026-11-23T10:00:00Z"}`}, "counts 2 records where 1"},
		"a newer change":      {[]string{head, line, `{"records":1,"modified":"2026-11-24T10:00:00Z"}`}, "newest change"},
		"text after":          {[]string{head, line, tail, `{"records":1}`}, "text follows"},
		"a stray brace after": {[]string{head, line, tail, `}`}, "text follows"},
		"no records":          {[]string{head, `{"records":0,"modified":""}`}, "no record of Alpine:v3.20"},
		"an unknown field":    {[]string{head, strings.Replace(line, `"id"`, `"extra":1,"id"`, 1), tail}, "unknown field"},
		"a record elsewhere":  {[]string{head, strings.Replace(line, `"Alpine:v3.20"`, `"Alpine:v3.19"`, 1), tail}, "not Alpine:v3.20"},
		"a malformed CVE":     {[]string{head, strings.Replace(line, "CVE-2026-1234", "CVE-26-1", 1), tail}, "not a CVE"},
		"CVEs out of order":   {[]string{head, strings.Replace(line, `["CVE-2026-1234"]`, `["CVE-2026-2","CVE-2026-1"]`, 1), tail}, "once each, in order"},
		"no introduced event": {[]string{head, strings.Replace(line, `{"introduced":"0"},`, "", 1), tail}, "no introduced event"},
		"not gzip":            {nil, "not kept OSV records"},
	} {
		data := []byte("plain text")
		if tt.lines != nil {
			data = keptData(t, tt.lines...)
		}
		if _, err := d.Check(bytes.NewReader(data), alpine); err == nil || !strings.Contains(err.Error(), tt.reason) {
			t.Errorf("%s: gave %v, want it refused naming %q", name, err, tt.reason)
		}
	}
}

// Records gives every kept record, in order, as Check judges it; an error the
// consumer returns ends the read with that error, and records given before a
// trailer that does not count them end in an error, so none may be used.
func TestRecords(t *testing.T) {
	r := recordings[0]
	host := r.host
	d := dump(t, r.id)
	kept, err := keep(t, d, recorded(t, r.file, r.sum), &host)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	facts, err := d.Records(bytes.NewReader(kept), &host, func(rec vulnrecord.Record) error {
		ids = append(ids, rec.ID)
		return nil
	})
	if err != nil || !slices.Equal(ids, keptIDs(t, kept)) || facts.Version != r.release {
		t.Errorf("records %q, %+v, %v; want %q", ids, facts, err, keptIDs(t, kept))
	}

	stop := errors.New("enough")
	if _, err := d.Records(bytes.NewReader(kept), &host, func(vulnrecord.Record) error { return stop }); !errors.Is(err, stop) {
		t.Errorf("a consumer's error gave %v", err)
	}

	alpine := &osfingerprint.OSInfo{OS: "linux", Platform: "alpine", PlatformVersion: "3.20.10"}
	head := `{"format":1,"release":"Alpine:v3.20"}`
	line := `{"id":"A-1","cves":[],"modified":"2026-11-23T10:00:00Z","affected":[{"package":"openssl","ecosystem":"Alpine:v3.20","ranges":[[{"introduced":"0"}]]}]}`
	given := 0
	if _, err := d.Records(bytes.NewReader(keptData(t, head, line, `{"records":2,"modified":"2026-11-23T10:00:00Z"}`)), alpine, func(vulnrecord.Record) error {
		given++
		return nil
	}); err == nil || given != 1 {
		t.Errorf("a miscounted trailer gave %v after %d records", err, given)
	}
}

// The rating an advisory's title opens with is kept, as written, and nothing
// else of the title: Rocky Linux's and AlmaLinux's advisories open with one
// and Alpine's records have no title. A title that opens with another word
// gives none, a kept rating that is not one is refused, and records kept
// before ratings were are still read.
func TestRating(t *testing.T) {
	for summary, want := range map[string]string{
		"Important: kernel security update":            "Important",
		"Critical: php:7.2 security update":            "Critical",
		"Moderate: python36:3.6 security update":       "Moderate",
		"Low: libwmf security update":                  "Low",
		"None: kernel bug fix and enhancement update":  "",
		"container-tools bug fix update":               "",
		"Red Hat Security Advisory: quagga security":   "",
		"ALSA-2022:5468: php:8.0 security (Important)": "",
		"Important:kernel with no space":               "",
		"":                                             "",
	} {
		if got := (record{Summary: summary}).rating(); got != want {
			t.Errorf("%q: rating %q, want %q", summary, got, want)
		}
	}

	rocky := recordings[2]
	host := rocky.host
	kept, err := keep(t, dump(t, rocky.id), recorded(t, rocky.file, rocky.sum), &host)
	if err != nil {
		t.Fatal(err)
	}
	rated := map[string]int{}
	if _, err := dump(t, rocky.id).Records(bytes.NewReader(kept), &host, func(r vulnrecord.Record) error {
		rated[r.Rating]++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if rated["Important"] == 0 || rated["Moderate"] == 0 || rated[""] != 0 {
		t.Errorf("Rocky Linux's excerpt kept the ratings %v, want every advisory rated", rated)
	}

	alpine := &osfingerprint.OSInfo{OS: "linux", Platform: "alpine", PlatformVersion: "3.20.10"}
	head := `{"format":1,"release":"Alpine:v3.20"}`
	line := `{"id":"A-1","cves":[],"modified":"2026-11-23T10:00:00Z","rating":"Severe","affected":[{"package":"openssl","ecosystem":"Alpine:v3.20","ranges":[[{"introduced":"0"}]]}]}`
	tail := `{"records":1,"modified":"2026-11-23T10:00:00Z"}`
	if _, err := dump(t, "osv-alpine").Check(bytes.NewReader(keptData(t, head, line, tail)), alpine); err == nil || !strings.Contains(err.Error(), "not an advisory's rating") {
		t.Errorf("a kept rating that is not one gave %v", err)
	}
	unrated := strings.Replace(line, `"rating":"Severe",`, "", 1)
	if _, err := dump(t, "osv-alpine").Check(bytes.NewReader(keptData(t, head, unrated, tail)), alpine); err != nil {
		t.Errorf("records kept without a rating were refused: %v", err)
	}
}

// A dump names the release a match of host reads, the Version that match
// carries, and refuses a host it does not apply to or whose version names no
// release.
func TestDumpRelease(t *testing.T) {
	d := dump(t, "osv-ubuntu")
	if got, err := d.Release(&osfingerprint.OSInfo{OS: "linux", Platform: "ubuntu", PlatformVersion: "26.04"}); err != nil || got != "Ubuntu:26.04" {
		t.Errorf("Ubuntu 26.04: %q, %v", got, err)
	}
	for name, host := range map[string]*osfingerprint.OSInfo{
		"another distribution": {OS: "linux", Platform: "debian", PlatformVersion: "12"},
		"no release":           {OS: "linux", Platform: "ubuntu", PlatformVersion: "jammy"},
	} {
		if got, err := d.Release(host); err == nil {
			t.Errorf("%s: %q, want it refused", name, got)
		}
	}
}

// A kept record is given to matching with each event of its ranges the bound
// it names, introduced from, fixed before, last affected up to, and a limit
// the range's end, and with the rest of the record as it was kept.
func TestRecordMatching(t *testing.T) {
	kept := Record{ID: "USN-1-1", CVEs: []string{"CVE-2026-1"}, Published: "2026-11-01T00:00:00Z", Modified: "2026-11-02T00:00:00Z",
		Advisory: "https://ubuntu.com/security/notices/USN-1-1", Rating: "Important",
		Severity: []Severity{{Type: "Ubuntu", Score: "medium"}},
		Affected: []Affected{{Package: "openssl", Ecosystem: "Ubuntu:26.04", Ranges: [][]Event{
			{{"introduced": "0"}, {"fixed": "3.0.2-2"}},
			{{"introduced": "1.0"}, {"last_affected": "1.9"}, {"limit": "2.0"}},
		}}}}
	got := kept.matching()
	want := vulnrecord.Record{ID: "USN-1-1", CVEs: []string{"CVE-2026-1"}, Published: "2026-11-01T00:00:00Z", Modified: "2026-11-02T00:00:00Z",
		Advisory: "https://ubuntu.com/security/notices/USN-1-1", Rating: "Important",
		Scores: []vulnrecord.Score{{Type: "Ubuntu", Score: "medium"}},
		Affected: []vulnrecord.Affected{{Package: "openssl", Ecosystem: "Ubuntu:26.04", Ranges: [][]vulnrecord.Bound{
			{{Kind: vulnrecord.From, Version: "0"}, {Kind: vulnrecord.Before, Version: "3.0.2-2"}},
			{{Kind: vulnrecord.From, Version: "1.0"}, {Kind: vulnrecord.UpTo, Version: "1.9"}, {Kind: vulnrecord.Limit, Version: "2.0"}},
		}}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("matching gave\n%+v\nwant\n%+v", got, want)
	}
}
