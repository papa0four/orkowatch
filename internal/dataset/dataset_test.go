// internal/dataset/dataset_test.go

package dataset

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/papa0four/orkowatch/internal/osfingerprint"
)

// testDataset is a dataset made for the tests, holding at most 1 KiB.
type testDataset struct{}

func (testDataset) ID() string                           { return "test-data" }
func (testDataset) AppliesTo(*osfingerprint.OSInfo) bool { return true }
func (testDataset) MaxBytes() int64                      { return 1 << 10 }
func (testDataset) Origin() Origin                       { return Origin{} }

func (testDataset) Check(io.Reader, *osfingerprint.OSInfo) (Facts, error) { return Facts{}, nil }

var now = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

// goodManifest is a manifest of testDataset that Validate accepts.
func goodManifest() Manifest {
	return Manifest{
		Format:      ManifestFormat,
		ID:          "test-data",
		Source:      "https://data.example/test.json",
		Fetched:     now.Add(-time.Hour),
		SHA256:      strings.Repeat("ab", 32),
		Size:        512,
		License:     "CC0 1.0",
		Attribution: "Made for the tests",
	}
}

func TestValidID(t *testing.T) {
	for id, want := range map[string]bool{
		"kev":                   true,
		"debian-12":             true,
		"ubuntu-22-04":          true,
		"":                      false,
		"KEV":                   false,
		"-kev":                  false,
		"kev-":                  false,
		"kev--epss":             false,
		"../kev":                false,
		"kev/epss":              false,
		`kev\epss`:              false,
		"kev.json":              false,
		strings.Repeat("a", 64): true,
		strings.Repeat("a", 65): false,
	} {
		if got := ValidID(id); got != want {
			t.Errorf("ValidID(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestValidCVE(t *testing.T) {
	for id, want := range map[string]bool{
		"CVE-1999-0001":                       true,
		"CVE-2026-123456":                     true,
		"CVE-2026-" + strings.Repeat("9", 19): true,
		"CVE-2026-" + strings.Repeat("9", 20): false,
		"CVE-2026-123":                        false,
		"CVE-26-1234":                         false,
		"cve-2026-1234":                       false,
		"CVE-2026-1234 ":                      false,
		"CVE-2026-1234\n":                     false,
		"GHSA-2026-1234":                      false,
		"":                                    false,
	} {
		if got := ValidCVE(id); got != want {
			t.Errorf("ValidCVE(%q) = %v, want %v", id, got, want)
		}
	}
}

// A manifest round-trips through Encode and DecodeManifest, and is accepted.
func TestManifestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := goodManifest().Encode(&buf); err != nil {
		t.Fatal(err)
	}
	m, err := DecodeManifest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if m != goodManifest() {
		t.Errorf("decoded %+v, want %+v", m, goodManifest())
	}
	if err := m.Validate(testDataset{}, now); err != nil {
		t.Errorf("a good manifest was refused: %v", err)
	}
}

// A manifest that is too large, holds a field this version does not know, is
// not JSON, or has text after it, is refused before anything in it is used.
func TestDecodeManifestRefuses(t *testing.T) {
	var good bytes.Buffer
	if err := goodManifest().Encode(&good); err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{
		"too large":      `{"id":"` + strings.Repeat("a", maxManifestBytes) + `"}`,
		"an unknown key": strings.Replace(good.String(), `"format"`, `"extra": 1, "format"`, 1),
		"not JSON":       "id = test-data",
		"text after it":  good.String() + `{"id":"other"}`,
		"empty":          "",
	} {
		if _, err := DecodeManifest(strings.NewReader(text)); !errors.Is(err, ErrManifest) {
			t.Errorf("%s: gave %v, want ErrManifest", name, err)
		}
	}
}

// Each way a manifest can misdescribe its dataset is refused.
func TestValidateRefuses(t *testing.T) {
	for name, change := range map[string]func(*Manifest){
		"another format":           func(m *Manifest) { m.Format = ManifestFormat + 1 },
		"an id that is a path":     func(m *Manifest) { m.ID = "../test-data" },
		"another dataset's id":     func(m *Manifest) { m.ID = "other-data" },
		"no fetch time":            func(m *Manifest) { m.Fetched = time.Time{} },
		"a fetch time to come":     func(m *Manifest) { m.Fetched = now.Add(time.Second) },
		"a short checksum":         func(m *Manifest) { m.SHA256 = "abcd" },
		"an upper-case checksum":   func(m *Manifest) { m.SHA256 = strings.Repeat("AB", 32) },
		"a checksum not in hex":    func(m *Manifest) { m.SHA256 = strings.Repeat("zz", 32) },
		"no size":                  func(m *Manifest) { m.Size = 0 },
		"a size over the limit":    func(m *Manifest) { m.Size = testDataset{}.MaxBytes() + 1 },
		"a plain HTTP source":      func(m *Manifest) { m.Source = "http://data.example/test.json" },
		"a source with no host":    func(m *Manifest) { m.Source = "https:///test.json" },
		"a source with a password": func(m *Manifest) { m.Source = "https://user:pw@data.example/test.json" },
		"a license with an escape": func(m *Manifest) { m.License = "CC0\x1b[2J" },
		"an attribution too long":  func(m *Manifest) { m.Attribution = strings.Repeat("a", maxTextLen+1) },
	} {
		m := goodManifest()
		change(&m)
		if err := m.Validate(testDataset{}, now); !errors.Is(err, ErrManifest) {
			t.Errorf("%s: gave %v, want ErrManifest", name, err)
		}
	}

	// The limits themselves are accepted.
	m := goodManifest()
	m.Fetched, m.Size = now, testDataset{}.MaxBytes()
	if err := m.Validate(testDataset{}, now); err != nil {
		t.Errorf("a manifest at its limits was refused: %v", err)
	}
}

// A dataset is current for seven days after it is fetched, out of sync for
// the seven after that, and stale from then on. The days are written out
// rather than taken from the constants, so a change to either is a change
// this test sees.
func TestStateAt(t *testing.T) {
	const day = 24 * time.Hour
	fetched := now
	for _, tt := range []struct {
		age  time.Duration
		want State
	}{
		{0, StateCurrent},
		{6 * day, StateCurrent},
		{7 * day, StateCurrent},
		{7*day + time.Second, StateOutOfSync},
		{13 * day, StateOutOfSync},
		{14 * day, StateOutOfSync},
		{14*day + time.Second, StateStale},
		{30 * day, StateStale},
	} {
		if got := StateAt(fetched, fetched.Add(tt.age)); got != tt.want {
			t.Errorf("at %v after the fetch the state is %q, want %q", tt.age, got, tt.want)
		}
	}
}

// An origin's hosts are its address's own and the redirect hosts it lists,
// in lower case; an address that is not HTTPS, and a redirect host that is a
// path or holds a port, are refused.
func TestOriginHosts(t *testing.T) {
	hosts, err := Origin{URL: "https://Data.Example/kev.json", RedirectHosts: []string{"CDN.example"}}.Hosts()
	if err != nil || len(hosts) != 2 || hosts[0] != "data.example" || hosts[1] != "cdn.example" {
		t.Errorf("hosts %q, %v", hosts, err)
	}
	for name, o := range map[string]Origin{
		"plain HTTP":           {URL: "http://data.example/kev.json"},
		"no address":           {},
		"a redirect with path": {URL: "https://data.example/k", RedirectHosts: []string{"cdn.example/x"}},
		"a redirect with port": {URL: "https://data.example/k", RedirectHosts: []string{"cdn.example:8443"}},
		"an empty redirect":    {URL: "https://data.example/k", RedirectHosts: []string{""}},
	} {
		if _, err := o.Hosts(); !errors.Is(err, ErrManifest) {
			t.Errorf("%s: gave %v, want it refused", name, err)
		}
	}
}
