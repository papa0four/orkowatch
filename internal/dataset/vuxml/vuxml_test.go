// internal/dataset/vuxml/vuxml_test.go

package vuxml

import (
	"bytes"
	"compress/bzip2"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/softwarelist"
	"github.com/papa0four/orkowatch/internal/vulnmatch"
	"github.com/papa0four/orkowatch/internal/vulnrecord"
)

// excerpt is a recorded excerpt of vuln.xml.bz2 as vuxml.freebsd.org served
// it on 2026-11-26: its declaration, DOCTYPE, and copyright notice as the
// document gives them, its 30 newest entries, and entries of each shape a
// range takes, a cancelled entry, and entries naming no CVE or an old CAN-
// name, 39 in all, compressed with bzip2.
const (
	excerpt    = "testdata/vuln-2026-11-26-excerpt.xml.bz2"
	excerptSum = "ab5396d3f47eba6351fb4b4a98fce6171026c1cebe9398416dc734429502ec13"
)

var freebsd = &osfingerprint.OSInfo{OS: "freebsd", Platform: "freebsd", PlatformVersion: "15.1-RELEASE"}

// recorded is the excerpt, refused when it is not the file recorded.
func recorded(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(excerpt)
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(data); hex.EncodeToString(got[:]) != excerptSum {
		t.Fatalf("%s hashes to %x, not what was recorded", excerpt, got)
	}
	return data
}

// records reads data as the document for FreeBSD and gives its entries by
// their identifiers.
func records(t *testing.T, data []byte) (map[string]vulnrecord.Record, error) {
	t.Helper()
	got := map[string]vulnrecord.Record{}
	_, err := Document{}.Records(bytes.NewReader(data), freebsd, func(r vulnrecord.Record) error {
		got[r.ID] = r
		return nil
	})
	return got, err
}

// The document names itself, applies to FreeBSD hosts alone, and is fetched
// from vuxml.freebsd.org as bzip2, under its license; a FreeBSD match of it
// carries one release whatever the host's.
func TestDocumentStatesItself(t *testing.T) {
	d := Document{}
	if d.ID() != "vuxml" || d.Manager() != softwarelist.ManagerPkg || d.MaxBytes() != 8<<20 {
		t.Errorf("id %q, manager %q, max %d", d.ID(), d.Manager(), d.MaxBytes())
	}
	if o := d.Origin(); o.URL != "https://vuxml.freebsd.org/freebsd/vuln.xml.bz2" || o.License != "BSD 2-clause" || o.Attribution == "" {
		t.Errorf("origin %+v", o)
	}
	for host, want := range map[*osfingerprint.OSInfo]bool{
		freebsd: true,
		{OS: "freebsd", Platform: "freebsd", PlatformVersion: "14.3-RELEASE"}: true,
		{OS: "linux", Platform: "ubuntu", PlatformVersion: "26.04"}:           false,
		nil: false,
	} {
		if got := d.AppliesTo(host); got != want {
			t.Errorf("applies to %+v: %v", host, got)
		}
	}
	if got, err := d.Release(freebsd); err != nil || got != "FreeBSD ports" {
		t.Errorf("release %q, %v", got, err)
	}
	if _, err := d.Release(&osfingerprint.OSInfo{OS: "linux"}); err == nil {
		t.Error("a Linux host was given a release")
	}
}

// Each entry of the excerpt is given as matching reads it: its CVEs, the
// page pkg audit names for it, and each name of each package with its
// ranges, a range with no lower bound from the first version and a bare *
// the first version, as pkg reads it. A cancelled entry is not given, a CAN-
// name is left out, a name a package gives twice is given once, and the
// document's date is its newest.
func TestRecordsOfTheExcerpt(t *testing.T) {
	data := recorded(t)
	facts, err := Document{}.Check(bytes.NewReader(data), freebsd)
	if err != nil || facts.Version != "FreeBSD ports" || !facts.Date.Equal(time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("facts %+v, %v", facts, err)
	}
	got, err := records(t, data)
	if err != nil || len(got) != 38 {
		t.Fatalf("%d records, %v", len(got), err)
	}
	from := func(v string) vulnrecord.Bound { return vulnrecord.Bound{Kind: vulnrecord.From, Version: v} }
	before := func(v string) vulnrecord.Bound { return vulnrecord.Bound{Kind: vulnrecord.Before, Version: v} }
	after := func(v string) vulnrecord.Bound { return vulnrecord.Bound{Kind: vulnrecord.After, Version: v} }
	exactly := func(v string) vulnrecord.Bound { return vulnrecord.Bound{Kind: vulnrecord.Exactly, Version: v} }
	ranges := func(r vulnrecord.Record, name string) [][]vulnrecord.Bound {
		for _, a := range r.Affected {
			if a.Package == name {
				return a.Ranges
			}
		}
		return nil
	}

	psgi := got["a22c60b3-e987-11f1-97dc-40b034429ecf"]
	if !slices.Equal(psgi.CVEs, []string{"CVE-2026-120637", "CVE-2026-120638", "CVE-2026-120639", "CVE-2026-120647"}) ||
		psgi.Advisory != "https://vuxml.FreeBSD.org/freebsd/a22c60b3-e987-11f1-97dc-40b034429ecf.html" ||
		!reflect.DeepEqual(ranges(psgi, "p5-CGI-PSGI"), [][]vulnrecord.Bound{{from("0"), before("0.16")}}) ||
		psgi.Affected[0].Ecosystem != "FreeBSD ports" {
		t.Errorf("an upper bound alone: %+v", psgi)
	}
	for name, c := range map[string]struct {
		vid, pkg string
		want     [][]vulnrecord.Bound
	}{
		"exactly":                 {"b51a4121-9607-11f0-becf-00a098b42aeb", "pcre2", [][]vulnrecord.Bound{{exactly("10.45")}}},
		"before a bare *":         {"ec49f6b5-ee39-11e8-b2f4-74d435b63d51", "php70-imap", [][]vulnrecord.Bound{{from("0"), before("0")}}},
		"from a bare *":           {"d8382a69-4728-11e8-ba83-0011d823eebd", "polarssl13", [][]vulnrecord.Bound{{from("0")}}},
		"after a wildcard series": {"1e7f0c11-673a-11e5-98c8-60a44c524f57", "otrs", [][]vulnrecord.Bound{{after("3.2.*"), before("3.2.18")}, {after("3.3.*"), before("3.3.15")}, {after("4.0.*"), before("4.0.13")}}},
		"from the first version":  {"8cfb6f42-d2b0-11da-a672-000e0c2e438a", "p5-DBI-137", [][]vulnrecord.Bound{{from("0")}}},
	} {
		if r := ranges(got[c.vid], c.pkg); !reflect.DeepEqual(r, c.want) {
			t.Errorf("%s: %s has %+v, want %+v", name, c.pkg, r, c.want)
		}
	}
	if cves := got["8cfb6f42-d2b0-11da-a672-000e0c2e438a"].CVEs; len(cves) != 0 {
		t.Errorf("a CAN- name was given as a CVE: %q", cves)
	}
	if _, ok := got["187ab98e-2953-4495-b379-4060bd4b75ee"]; ok {
		t.Error("a cancelled entry was given")
	}
	var roundcube []string
	for _, a := range got["b8fc42ea-e738-11f1-b58b-8447094a420f"].Affected {
		roundcube = append(roundcube, a.Package)
	}
	if !slices.Equal(roundcube, []string{"roundcube-php82", "roundcube-php83", "roundcube-php84", "roundcube-php85"}) {
		t.Errorf("a name given twice: %q", roundcube)
	}
}

// Matched as pkg's packages are, the excerpt's entries say of each version
// what pkg audit 2.6.2 said of it in a FreeBSD 15.1 guest on 2026-11-26, for
// the same document: p5-CGI-PSGI 0.15 is affected and 0.16, its fix, is
// not; php70-imap, whose range is before a bare *, is not; and polarssl13,
// whose range is from a bare *, is.
func TestMatchesAsPkgAuditDid(t *testing.T) {
	got, err := records(t, recorded(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, version string
		affected      bool
	}{
		{"p5-CGI-PSGI", "0.15", true},
		{"p5-CGI-PSGI", "0.16", false},
		{"php70-imap", "7.0.0", false},
		{"polarssl13", "1.3.0", true},
	} {
		m, err := vulnmatch.New(softwarelist.ManagerPkg, []softwarelist.SoftwareEntry{{Name: c.name, Version: c.version, Manager: softwarelist.ManagerPkg, Source: "x/" + c.name}})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range got {
			if err := m.Add(r); err != nil {
				t.Fatal(err)
			}
		}
		if affected := len(m.Result().Packages) > 0; affected != c.affected {
			t.Errorf("%s %s affected %v, pkg audit said %v", c.name, c.version, affected, c.affected)
		}
	}
}

// document is a VuXML document of the entries given.
func document(entries ...string) string {
	return `<?xml version="1.0" encoding="utf-8"?>` + "\n" + `<vuxml xmlns="http://www.vuxml.org/apps/vuxml-1">` + strings.Join(entries, "\n") + "</vuxml>\n"
}

// vuln is an entry of the identifier given, holding body.
func vuln(vid, body string) string {
	return `<vuln vid="` + vid + `"><topic>t</topic>` + body + `<dates><discovery>2026-01-01</discovery><entry>2026-01-02</entry></dates></vuln>`
}

// sound is the body of an entry with one package and one range.
const sound = `<affects><package><name>curl</name><range><lt>8.0</lt></range></package></affects><references><cvename>CVE-2026-1</cvename></references>`

const vid = "a22c60b3-e987-11f1-97dc-40b034429ecf"

// A document that is not VuXML in the form vuxml.freebsd.org publishes is
// refused, with the reason, and no entry of it may be used: one that is not
// bzip2, one cut short, one of another root, one that refers to an entity,
// one that expands past its limit, one with no entry, and an entry with an
// identifier that is not a UUID, a bound that is not one, no package, or no
// date it was entered.
func TestRefuses(t *testing.T) {
	data := recorded(t)
	if _, err := (Document{}).Check(strings.NewReader(document(vuln(vid, sound))), freebsd); err == nil {
		t.Error("a document that is not bzip2 was taken")
	}
	if _, err := (Document{}).Check(bytes.NewReader(data[:len(data)/2]), freebsd); err == nil {
		t.Error("a document cut short was taken")
	}
	if _, err := (Document{}).Check(bytes.NewReader(data), &osfingerprint.OSInfo{OS: "linux"}); err == nil {
		t.Error("the document was read for a Linux host")
	}
	if _, err := read(bzip2.NewReader(bytes.NewReader(data)), 1000, nil); err == nil || err.Error() != "the document expands past 1000 bytes" {
		t.Errorf("past its limit: %v", err)
	}
	if facts, err := read(strings.NewReader(document(vuln(vid, sound))), maxExpanded, nil); err != nil || facts.Version != "FreeBSD ports" ||
		!facts.Date.Equal(time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("a sound document gave %+v, %v", facts, err)
	}
	for name, c := range map[string]struct {
		doc, want string
	}{
		"another root":         {`<html><body/></html>`, "not VuXML: the document is html"},
		"an entity":            {document("&vuln-2026;"), "the document ends before its last entry"},
		"no entry":             {document(), "the document holds no entry"},
		"text between entries": {document("words", vuln(vid, sound)), "the document holds text between its entries"},
		"an element after":     {document(vuln(vid, sound)) + "<vuxml/>", "the document holds an element after its end"},
		"another element":      {document(`<html/>`), "html is not an entry of VuXML"},
		"an identifier":        {document(vuln("42", sound)), "entry 42: its identifier is not a UUID"},
		"a bound":              {document(vuln(vid, `<affects><package><name>curl</name><range><ne>8.0</ne></range></package></affects>`)), `"ne" is not a bound of a range`},
		"an empty range":       {document(vuln(vid, `<affects><package><name>curl</name><range></range></package></affects>`)), "a range has no bound"},
		"no range":             {document(vuln(vid, `<affects><package><name>curl</name></package></affects>`)), "curl has no range of versions"},
		"no package":           {document(vuln(vid, `<references><cvename>CVE-2026-1</cvename></references>`)), "it names no package"},
		"no date entered": {document(`<vuln vid="` + vid + `">` + sound + `<dates><discovery>2026-01-01</discovery></dates></vuln>`),
			"it gives no date it was entered"},
		"a date": {document(`<vuln vid="` + vid + `">` + sound + `<dates><entry>yesterday</entry></dates></vuln>`), `"yesterday" is not a date`},
	} {
		if _, err := read(strings.NewReader(c.doc), maxExpanded, nil); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// An error each returns ends the read with that error.
func TestRecordsEndAtAnError(t *testing.T) {
	stop := errors.New("enough")
	given := 0
	_, err := Document{}.Records(bytes.NewReader(recorded(t)), freebsd, func(vulnrecord.Record) error {
		given++
		return stop
	})
	if !errors.Is(err, stop) || given != 1 {
		t.Errorf("%v after %d records", err, given)
	}
	if _, err := read(io.MultiReader(strings.NewReader(document(vuln(vid, sound)))), maxExpanded, func(vulnrecord.Record) error { return stop }); !errors.Is(err, stop) {
		t.Errorf("a plain document: %v", err)
	}
}
