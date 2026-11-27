// internal/dataset/kev/kev_test.go

package kev

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
)

// The recorded catalog is the file CISA published at the catalog's address on
// 2026-11-23, whole and unchanged, compressed with gzip: catalog version
// 2026.11.23, released 2026-11-23T12:54:37.9646Z, 1,790 entries, 1,871,125
// bytes. CISA distributes the catalog under the Creative Commons 0 1.0
// license; use of it does not authorize use of the CISA Logo or DHS Seal and
// is not an endorsement by CISA or DHS.
const (
	recordedFile   = "testdata/known_exploited_vulnerabilities-2026-11-23.json.gz"
	recordedSHA256 = "776fdde0a5d4f412bfe8336ffb6da32294890a794cc374c5d4c72a99ae5db84c"
	recordedCount  = `"count": 1790,`
	recordedFirst  = `"cveID": "CVE-2026-129448"`
)

// recorded returns the recorded catalog as CISA published it, having checked
// that it is still that file.
func recorded(t *testing.T) []byte {
	t.Helper()
	compressed, err := os.ReadFile(recordedFile)
	if err != nil {
		t.Fatal(err)
	}
	z, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != recordedSHA256 {
		t.Fatalf("the recorded catalog hashes to %x, not what was recorded", sum)
	}
	return data
}

// changed returns data with the one occurrence of from replaced by to.
func changed(t *testing.T, data []byte, from, to string) []byte {
	t.Helper()
	if n := bytes.Count(data, []byte(from)); n != 1 {
		t.Fatalf("%q occurs %d times in the recorded catalog, want once", from, n)
	}
	return bytes.Replace(data, []byte(from), []byte(to), 1)
}

// The catalog as CISA published it is accepted, gives the time it was
// released, and is within what the dataset may hold.
func TestCheckAcceptsTheRecordedCatalog(t *testing.T) {
	data := recorded(t)
	facts, err := Catalog{}.Check(bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("the recorded catalog was refused: %v", err)
	}
	if want := time.Date(2026, 11, 23, 12, 54, 37, 964600000, time.UTC); !facts.Date.Equal(want) {
		t.Errorf("date of the data = %s, want %s", facts.Date, want)
	}
	if facts.Version != "2026.11.23" {
		t.Errorf("version of the data = %q, want the catalog version 2026.11.23", facts.Version)
	}
	if int64(len(data)) > (Catalog{}).MaxBytes() {
		t.Errorf("the recorded catalog holds %d bytes, more than the dataset may", len(data))
	}
}

// A field CISA's schema does not list is passed over, at the top and in an
// entry, since the catalog gains fields.
func TestCheckAllowsAnUnlistedField(t *testing.T) {
	data := changed(t, recorded(t), recordedCount, recordedCount+` "added": {"later": true},`)
	data = changed(t, data, recordedFirst, recordedFirst+`, "added": ["later"]`)
	if _, err := (Catalog{}).Check(bytes.NewReader(data), nil); err != nil {
		t.Errorf("a catalog with a field the schema does not list was refused: %v", err)
	}
}

// A catalog that is not whole, or is not the catalog, is refused with the
// reason.
func TestCheckRefuses(t *testing.T) {
	whole := recorded(t)
	entryEnd := bytes.Index(whole, []byte("},\n        {")) + 1
	if entryEnd <= 0 {
		t.Fatal("no end of a first entry in the recorded catalog")
	}
	for name, c := range map[string]struct {
		data []byte
		want string
	}{
		"cut short in an entry":       {whole[:len(whole)/2], "not the catalog's JSON"},
		"cut short and closed":        {append(bytes.Clone(whole[:entryEnd]), "]}"...), "states 1790 entries and holds 1"},
		"a count one too few":         {changed(t, whole, recordedCount, `"count": 1789,`), "states 1789 entries and holds 1790"},
		"no count":                    {changed(t, whole, recordedCount, ""), "states no count"},
		"a malformed CVE identifier":  {changed(t, whole, recordedFirst, `"cveID": "2026-129448"`), `entry 1 names "2026-129448"`},
		"an entry with no identifier": {changed(t, whole, recordedFirst, `"cve": "CVE-2026-129448"`), `entry 1 names ""`},
		"no catalog version":          {changed(t, whole, `"catalogVersion": "2026.11.23",`, ""), "states no catalog version"},
		"a release date with no time": {changed(t, whole, `"2026-11-23T12:54:37.9646Z"`, `"2026-11-23"`), "is not a date and time"},
		"text after the catalog":      {append(bytes.Clone(whole), "{}"...), "text follows the catalog"},
		"another JSON document":       {[]byte(`{"format": 1, "id": "kev", "size": 1871125}`), "states no catalog version"},
		"a JSON list":                 {[]byte(`[{"cveID": "CVE-2026-129448"}]`), "not the catalog's JSON"},
		"an empty catalog":            {[]byte(`{"catalogVersion": "2026.11.23", "dateReleased": "2026-11-23T12:54:37Z", "count": 0, "vulnerabilities": []}`), "holds no entries"},
		"nothing":                     {nil, "not the catalog's JSON"},
		"a CVE named twice": {smallCatalog(`{"cveID": "CVE-2026-0001"}`, `{"cveID": "CVE-2026-0001"}`),
			"entry 2 names CVE-2026-0001, which an earlier entry names"},
	} {
		_, err := Catalog{}.Check(bytes.NewReader(c.data), nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Check gave %v, want a refusal saying %q", name, err, c.want)
		}
	}
}

// Read gives every entry of the recorded catalog as the catalog writes it,
// nothing for a CVE it does not list, and for each CWE the number of entries
// that name it, counted here from the file as a generic JSON document.
func TestReadIndexesTheRecordedCatalog(t *testing.T) {
	data := recorded(t)
	x, _, err := Catalog{}.Read(bytes.NewReader(data), nil)
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Vulnerabilities []map[string]any `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	want := make(map[string]int)
	for _, e := range raw.Vulnerabilities {
		id := e["cveID"].(string)
		got, ok := x.Entry(id)
		if !ok || got.Added != e["dateAdded"] || got.Due != e["dueDate"] || got.Ransomware != e["knownRansomwareCampaignUse"] {
			t.Errorf("%s: entry %+v, %v, want the catalog's %v, %v, %v", id, got, ok, e["dateAdded"], e["dueDate"], e["knownRansomwareCampaignUse"])
		}
		named := make(map[string]bool)
		for _, cwe := range e["cwes"].([]any) {
			named[cwe.(string)] = true
		}
		for cwe := range named {
			want[cwe]++
		}
	}
	if len(want) == 0 {
		t.Fatal("the recorded catalog names no CWE")
	}
	for cwe, n := range want {
		if got := x.ClassCount(cwe); got != n {
			t.Errorf("%s counts %d entries, want %d", cwe, got, n)
		}
	}
	if got := x.ClassCount("CWE-306"); got != 43 {
		t.Errorf("CWE-306 counts %d entries, want the 43 the catalog of 2026-11-23 holds", got)
	}
	if _, ok := x.Entry("CVE-1999-0001"); ok || x.ClassCount("CWE-319") != 0 {
		t.Error("a CVE or a CWE the catalog does not list was given an entry or a count")
	}
}

// smallCatalog is a catalog of entries written out whole.
func smallCatalog(entries ...string) []byte {
	return []byte(fmt.Sprintf(`{"catalogVersion": "1", "dateReleased": "2026-11-23T12:54:37Z", "count": %d, "vulnerabilities": [%s]}`,
		len(entries), strings.Join(entries, ", ")))
}

// An entry that names a CWE twice is counted once under it.
func TestReadCountsEachEntryOnce(t *testing.T) {
	data := smallCatalog(`{"cveID": "CVE-2026-0001", "cwes": ["CWE-1", "CWE-1"]}`, `{"cveID": "CVE-2026-0002", "cwes": ["CWE-1"]}`)
	x, _, err := Catalog{}.Read(bytes.NewReader(data), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := x.ClassCount("CWE-1"); got != 2 {
		t.Errorf("two entries naming CWE-1, one of them twice, count %d, want 2", got)
	}
}

// An entry that names a great many CWEs is read in time linear in what it
// names, since the catalog is untrusted and fits that many within its size
// limit: counting each entry once must not compare every CWE with every other.
func TestReadIsLinearInWhatAnEntryNames(t *testing.T) {
	const named = 150000
	cwes := make([]string, named)
	for i := range cwes {
		cwes[i] = fmt.Sprintf("%q", fmt.Sprintf("CWE-%d", i))
	}
	data := smallCatalog(`{"cveID": "CVE-2026-0001", "cwes": [` + strings.Join(cwes, ",") + `]}`)
	if int64(len(data)) > (Catalog{}).MaxBytes() {
		t.Fatalf("the catalog holds %d bytes, more than the dataset may", len(data))
	}
	start := time.Now()
	x, _, err := Catalog{}.Read(bytes.NewReader(data), nil)
	if took := time.Since(start); err != nil || took > 2*time.Second || x.ClassCount("CWE-149999") != 1 {
		t.Errorf("an entry naming %d CWEs took %s to read, %v", named, took, err)
	}
}

// The catalog names itself, its source, and its terms as a dataset must: a
// name the store can hold, an HTTPS address on CISA's host with no other host
// to follow, and a license and attribution a manifest accepts.
func TestCatalogStatesItsSource(t *testing.T) {
	c := Catalog{}
	if !dataset.ValidID(c.ID()) || !c.AppliesTo(nil) {
		t.Errorf("ID %q valid = %v, applies to any host = %v", c.ID(), dataset.ValidID(c.ID()), c.AppliesTo(nil))
	}
	hosts, err := c.Origin(nil).Hosts()
	if err != nil || len(hosts) != 1 || hosts[0] != "www.cisa.gov" {
		t.Errorf("hosts a fetch may reach = %q, %v, want www.cisa.gov alone", hosts, err)
	}
	data := recorded(t)
	sum := sha256.Sum256(data)
	now := time.Date(2026, 11, 23, 13, 0, 0, 0, time.UTC)
	m := dataset.Manifest{
		Format: dataset.ManifestFormat, ID: c.ID(), Source: c.Origin(nil).URL, Fetched: now,
		SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data)),
		License: c.Origin(nil).License, Attribution: c.Origin(nil).Attribution,
	}
	if err := m.Validate(c, now); err != nil {
		t.Errorf("a manifest of the recorded catalog was refused: %v", err)
	}
}
