// internal/security/checker/setting_test.go

package checker

import (
	"errors"
	"io/fs"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// A setting is recorded with its value and where it is, then what else was
// observed of it, and one no file states is recorded as not set. Every
// reader's evidence of a setting is built here, so they cannot differ.
func TestSettingEvidence(t *testing.T) {
	set := setting{value: "never", file: "etc/nslcd.conf", line: 7}
	if got := set.at(); got != "/etc/nslcd.conf:7" {
		t.Errorf("at %q", got)
	}

	got := settingEvidence("tls_reqcert", set, fact(finding.FactVersion, "0.9"))
	want := finding.Evidence{Kind: string(finding.KindSetting), Subject: "tls_reqcert", Facts: []finding.Fact{
		{Name: string(finding.FactValue), Value: "never"},
		{Name: string(finding.FactLine), Value: "/etc/nslcd.conf:7"},
		{Name: string(finding.FactVersion), Value: "0.9"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("a setting a file states: %+v, want %+v", got, want)
	}

	got = unsetEvidence("ssl", fact(finding.FactVersion, "0.9"))
	want = finding.Evidence{Kind: string(finding.KindSetting), Subject: "ssl", Facts: []finding.Fact{
		{Name: string(finding.FactState), Value: "not set"},
		{Name: string(finding.FactVersion), Value: "0.9"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("a setting no file states: %+v, want %+v", got, want)
	}
}

// A release is its major and minor number, whatever follows them, and text
// without both is not one.
func TestParseRelease(t *testing.T) {
	for text, want := range map[string]programRelease{
		"1.19.2":      {major: 1, minor: 19, text: "1.19.2"},
		"2.10":        {major: 2, minor: 10, text: "2.10"},
		"2.9.4-1.el9": {major: 2, minor: 9, text: "2.9.4-1.el9"},
	} {
		got, ok := parseRelease(text)
		if !ok || got != want {
			t.Errorf("%q: %+v %v, want %+v", text, got, ok, want)
		}
	}
	for _, text := range []string{"", "2", "two.ten", "2.x", "v2.10", "2.10-rc1"} {
		if got, ok := parseRelease(text); ok {
			t.Errorf("%q was read as the release %+v", text, got)
		}
	}

	release := programRelease{major: 2, minor: 10}
	for _, tc := range []struct {
		major, minor int
		want         bool
	}{
		{2, 10, true}, {2, 9, true}, {1, 99, true}, {2, 11, false}, {3, 0, false},
	} {
		if got := release.atLeast(tc.major, tc.minor); got != tc.want {
			t.Errorf("2.10 at least %d.%d: %v", tc.major, tc.minor, got)
		}
	}
	if got := (programRelease{major: 1, minor: 20, text: "1.20.1"}).series(); got != "1.20" {
		t.Errorf("series %q", got)
	}
}

// A file is read with who owns it, and the reason it could not be is the
// one every rule on a file's ownership reports. Its evidence carries its mode
// and owner as the account databases write them, and what was expected.
func TestStatOwned(t *testing.T) {
	fsys := fstest.MapFS{"etc/secret.conf": {Data: []byte("x"), Mode: 0o640}}
	owner := func(fs.FileInfo) (uint32, uint32, bool) { return 0, 42, true }

	file, unread := statOwned(fsys, "etc/secret.conf", owner)
	if unread != "" {
		t.Fatalf("a file that is there: %q", unread)
	}
	if read, write := file.excess(localAccount{}); !read || write {
		t.Errorf("0640 root:42 with no service account: read %v, write %v", read, write)
	}
	if read, _ := file.excess(localAccount{gid: 42, group: true}); read {
		t.Error("0640 root:42 is read as open to others than the service group")
	}
	want := finding.Evidence{Kind: string(finding.KindFile), Subject: "/etc/secret.conf", Facts: []finding.Fact{
		{Name: string(finding.FactMode), Value: "-rw-r-----"},
		{Name: string(finding.FactUID), Value: "0"},
		{Name: string(finding.FactGID), Value: "42"},
		{Name: string(finding.FactExpected), Value: expectRootOnly},
		{Name: string(finding.FactVersion), Value: "2.9"},
	}}
	if got := file.evidence(expectRootOnly, fact(finding.FactVersion, "2.9")); !reflect.DeepEqual(got, want) {
		t.Errorf("evidence %+v, want %+v", got, want)
	}

	if _, unread := statOwned(fsys, "etc/absent.conf", owner); unread != "/etc/absent.conf could not be checked: "+errors.Join(&fs.PathError{Op: "open", Path: "etc/absent.conf", Err: fs.ErrNotExist}).Error() {
		t.Errorf("a file that is absent: %q", unread)
	}
	unowned := func(fs.FileInfo) (uint32, uint32, bool) { return 0, 0, false }
	if _, unread := statOwned(fsys, "etc/secret.conf", unowned); unread != "/etc/secret.conf ownership could not be determined" {
		t.Errorf("a file with no owner recorded: %q", unread)
	}
}
