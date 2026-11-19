// internal/security/checker/krb5_test.go

package checker

import (
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
)

// text is a file with the given content.
func text(content string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(content)} }

// runKerberos judges the Kerberos configuration in fsys on a host of family
// with the given release installed, or with none readable when release is
// empty.
func runKerberos(fsys fs.FS, family registry.Distro, release string) map[registry.FindingKey]finding.Condition {
	linux := registry.OSContext{Platform: registry.PlatformLinux, Families: []registry.Distro{family, registry.DistroGeneric}}
	r := &report{osCtx: linux, index: make(map[registry.FindingKey]int)}
	sssd, sssdErr := readSSSDConfig(fsys)
	recordKerberos(r, fsys, linux.Families, krb5Host{release: func() (krb5Release, error) {
		if release == "" {
			return krb5Release{}, errors.New("klist is not installed")
		}
		return parseKrb5Release("Kerberos 5 version " + release)
	}}, sssd, sssdErr)
	got := map[registry.FindingKey]finding.Condition{}
	for _, c := range r.finish().Conditions {
		got[registry.FindingKey(c.Key)] = c
	}
	return got
}

// The library of each family reads /etc/krb5.conf; the SUSE family's falls
// back to the vendor copy, and Alpine's reads both.
func TestKrb5ConfigFiles(t *testing.T) {
	both := fstest.MapFS{"etc/krb5.conf": text(""), "usr/etc/krb5.conf": text("")}
	vendor := fstest.MapFS{"usr/etc/krb5.conf": text("")}
	cases := []struct {
		name   string
		fsys   fs.FS
		family registry.Distro
		want   []string
	}{
		{"Debian, both present", both, registry.DistroDebian, []string{"etc/krb5.conf"}},
		{"Debian, vendor copy only", vendor, registry.DistroDebian, nil},
		{"SUSE, both present", both, registry.DistroSUSE, []string{"etc/krb5.conf"}},
		{"SUSE, vendor copy only", vendor, registry.DistroSUSE, []string{"usr/etc/krb5.conf"}},
		{"Alpine, both present", both, registry.DistroAlpine, []string{"etc/krb5.conf", "usr/etc/krb5.conf"}},
		{"none", fstest.MapFS{}, registry.DistroSUSE, nil},
	}
	for _, c := range cases {
		got, err := krb5ConfigFiles(c.fsys, []registry.Distro{c.family})
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v %v, want %v", c.name, got, err, c.want)
		}
	}
	if _, err := krb5ConfigFiles(statFailure{fstest.MapFS{}}, nil); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("a file whose presence is unknown: %v", err)
	}
}

// The first value of a relation is the one in force, an include is read where
// it is written, and an included directory gives its files in the order of
// their bytes.
func TestReadKrb5Config(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/krb5.conf": text("stray = ignored\n" +
			"includedir /etc/krb5.conf.d\n" +
			"[libdefaults]\n" +
			"\tdefault_realm = MAIN.TEST\n" +
			" permitted_enctypes = \"aes256-cts\"\n" +
			" default_realm = SECOND.TEST\n" +
			" MAIN.TEST = {\n  permitted_enctypes = rc4\n }\n" +
			" allow_weak_crypto=true\n" +
			"[realms]\n default_tkt_enctypes = rc4\n" +
			"[libdefaults]\n default_tkt_enctypes = aes128-cts # kept\n"),
		"etc/krb5.conf.d/B.conf":   text("[libdefaults]\n ticket_lifetime = from-B\n"),
		"etc/krb5.conf.d/a-policy": text("[libdefaults]\n ticket_lifetime = from-a\n default_realm = SNIPPET.TEST\n"),
		"etc/krb5.conf.d/.x.conf":  text("[libdefaults]\n ticket_lifetime = hidden\n"),
		"etc/krb5.conf.d/notes.md": text("[libdefaults]\n ticket_lifetime = notes\n"),
	}
	config, err := readKrb5Config(fsys, []string{"etc/krb5.conf"})
	if err != nil || len(config.refused) != 0 || len(config.undecided) != 0 {
		t.Fatalf("%v refused %v undecided %v", err, config.refused, config.undecided)
	}
	want := map[string]krb5Setting{
		"ticket_lifetime":      {"from-B", "etc/krb5.conf.d/B.conf", 2},
		"default_realm":        {"SNIPPET.TEST", "etc/krb5.conf.d/a-policy", 3},
		"permitted_enctypes":   {"aes256-cts", "etc/krb5.conf", 5},
		"allow_weak_crypto":    {"true", "etc/krb5.conf", 10},
		"default_tkt_enctypes": {"aes128-cts # kept", "etc/krb5.conf", 14},
	}
	if !reflect.DeepEqual(config.libdefaults, want) {
		t.Errorf("got  %+v\nwant %+v", config.libdefaults, want)
	}
	if wantFiles := []string{"etc/krb5.conf", "etc/krb5.conf.d/B.conf", "etc/krb5.conf.d/a-policy"}; !reflect.DeepEqual(config.files, wantFiles) {
		t.Errorf("files %v, want %v", config.files, wantFiles)
	}

	after, err := readKrb5Config(fstest.MapFS{
		"etc/krb5.conf": text("[libdefaults]\n default_realm = MAIN.TEST\ninclude /etc/extra\n"),
		"etc/extra":     text("[libdefaults]\n default_realm = EXTRA.TEST\n"),
	}, []string{"etc/krb5.conf"})
	if err != nil || after.libdefaults["default_realm"].value != "MAIN.TEST" {
		t.Errorf("an include after the relation took precedence: %+v", after.libdefaults)
	}
}

// What the library refuses is recorded, and a relation first set after a
// section marked final is left undecided.
func TestReadKrb5ConfigRefusedAndUndecided(t *testing.T) {
	refused := map[string]string{
		"a missing included file":      "include /etc/missing\n[libdefaults]\n",
		"a missing included directory": "includedir /etc/missing.d\n[libdefaults]\n",
		"a relative include":           "include extra\n[libdefaults]\n",
		"an indented include":          "[libdefaults]\n include /etc/krb5.conf\n",
		"a line with no equals sign":   "[libdefaults]\n default_realm MAIN.TEST\n",
		"a module directive":           "module /usr/lib/profile.so:residual\n",
		"an include of itself":         "include /etc/krb5.conf\n",
		"an unclosed section header":   "[libdefaults\n",
	}
	for name, content := range refused {
		config, err := readKrb5Config(fstest.MapFS{"etc/krb5.conf": text(content)}, []string{"etc/krb5.conf"})
		if err != nil || len(config.refused) != 1 || !strings.Contains(config.refused[0], "/etc/krb5.conf:") {
			t.Errorf("%s: refused %v, err %v", name, config.refused, err)
		}
	}

	final, err := readKrb5Config(fstest.MapFS{"etc/krb5.conf": text(
		"[libdefaults]*\n default_realm = MAIN.TEST\n[libdefaults]\n default_realm = LATER.TEST\n permitted_enctypes = rc4\n")},
		[]string{"etc/krb5.conf"})
	if err != nil || final.undecided["default_realm"] != "" || !strings.Contains(final.undecided["permitted_enctypes"], "/etc/krb5.conf:5") {
		t.Errorf("undecided %v", final.undecided)
	}
}

// With no configuration nothing is judged, and a host not seen to use
// Kerberos is not judged on a file its packages installed.
func TestRecordKerberosWithoutUse(t *testing.T) {
	for key, c := range runKerberos(fstest.MapFS{}, registry.DistroDebian, "1.19.2") {
		if c.Result != finding.ResultNotChecked {
			t.Errorf("no configuration: %s %+v", key, c)
		}
	}
	for _, key := range krb5Rules {
		if c := runKerberos(statFailure{fstest.MapFS{}}, registry.DistroDebian, "1.19.2")[key]; c.Result != finding.ResultError {
			t.Errorf("unreadable: %s %+v", key, c)
		}
	}

	packaged := runKerberos(fstest.MapFS{"etc/krb5.conf": text("[libdefaults]\n\tdefault_realm = ATHENA.MIT.EDU\n allow_weak_crypto = maybe\n")},
		registry.DistroDebian, "1.19.2")
	for _, key := range krb5Rules {
		if c := packaged[key]; c.Result != finding.ResultNotApplicable || !strings.Contains(c.Reason, "no keytab") {
			t.Errorf("packaged file, no use: %s %+v", key, c)
		}
	}
	present := packaged[ruleKrb5Present]
	if len(present.Evidence) != 1 || present.Evidence[0].Subject != "[libdefaults] default_realm" ||
		factText(present.Evidence[0]) != "value=ATHENA.MIT.EDU line=/etc/krb5.conf:2" {
		t.Errorf("default_realm on the presence condition: %+v", present)
	}
}

// Each rule is concluded from the lists in force on a host that uses Kerberos.
func TestRecordKerberosRules(t *testing.T) {
	host := func(lines ...string) fstest.MapFS {
		return fstest.MapFS{
			"etc/krb5.keytab": text("keytab"),
			"etc/krb5.conf":   text("[libdefaults]\n" + strings.Join(lines, "\n") + "\n"),
		}
	}
	policy := host()
	policy["etc/krb5.conf"] = text("includedir /etc/krb5.conf.d/\n[libdefaults]\n default_realm = X.TEST\n")
	policy["etc/krb5.conf.d/crypto-policies"] = text("[libdefaults]\npermitted_enctypes = aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128 camellia256-cts-cmac\n")

	cases := map[string]struct {
		fsys    fstest.MapFS
		family  registry.Distro
		release string
		key     registry.FindingKey
		want    finding.Result
		text    string
	}{
		"nothing set, Debian": {host(), registry.DistroDebian, "1.19.2", ruleKrb5Deprecated, finding.ResultFail,
			"[libdefaults] permitted_enctypes state=not set version=1.19.2 description=in force: des3-cbc-sha1, arcfour-hmac"},
		"nothing set, RHEL": {host(), registry.DistroRHEL, "1.21.1", ruleKrb5Deprecated, finding.ResultFail,
			"[libdefaults] permitted_enctypes state=not set version=1.21.1 description=in force: arcfour-hmac"},
		"nothing set, release not observed":   {host(), registry.DistroDebian, "1.23.0", ruleKrb5Deprecated, finding.ResultUnknown, "was not observed"},
		"nothing set, family not observed":    {host(), registry.DistroGeneric, "1.21.1", ruleKrb5Deprecated, finding.ResultUnknown, "was not observed"},
		"nothing set, release unreadable":     {host(), registry.DistroDebian, "", ruleKrb5Deprecated, finding.ResultUnknown, "was not observed"},
		"crypto-policies snippet":             {policy, registry.DistroRHEL, "1.21.1", ruleKrb5Deprecated, finding.ResultPass, ""},
		"DEFAULT -des3 -rc4":                  {host(" permitted_enctypes = DEFAULT -des3 -rc4"), registry.DistroDebian, "1.20.1", ruleKrb5Deprecated, finding.ResultPass, ""},
		"aes only, release unreadable":        {host(" permitted_enctypes = aes"), registry.DistroDebian, "", ruleKrb5Deprecated, finding.ResultPass, ""},
		"rc4 removed after it is named":       {host(" permitted_enctypes = rc4 -rc4 aes128-cts"), registry.DistroArch, "1.22.2", ruleKrb5Deprecated, finding.ResultPass, ""},
		"triple DES named on a Red Hat build": {host(" permitted_enctypes = des3 aes256-cts"), registry.DistroFedora, "1.21.3", ruleKrb5Deprecated, finding.ResultPass, ""},
		"triple DES named, build not observed": {host(" permitted_enctypes = des3 aes256-cts"), registry.DistroGeneric, "1.21.3", ruleKrb5Deprecated, finding.ResultUnknown,
			"triple DES types of this build"},
		"rc4 named after it is removed": {host(" permitted_enctypes = -rc4 RC4-HMAC,aes128-cts"), registry.DistroSUSE, "1.20.1", ruleKrb5Deprecated, finding.ResultFail,
			"[libdefaults] permitted_enctypes value=-rc4 RC4-HMAC,aes128-cts line=/etc/krb5.conf:2 description=in force: arcfour-hmac"},
		"ticket list names rc4": {host(" permitted_enctypes = aes256-cts", " default_tkt_enctypes = rc4"), registry.DistroAlpine, "1.21.3", ruleKrb5Deprecated, finding.ResultFail,
			"[libdefaults] default_tkt_enctypes value=rc4 line=/etc/krb5.conf:3 description=in force: arcfour-hmac"},
		"unknown name ignored": {host(" permitted_enctypes = aes256-cts des-cbc-crc"), registry.DistroDebian, "1.19.2", ruleKrb5Deprecated, finding.ResultPass, ""},

		"weak named, flag unset":  {host(" permitted_enctypes = aes256-cts arcfour-hmac-exp"), registry.DistroDebian, "1.19.2", ruleKrb5Weak, finding.ResultPass, ""},
		"weak named, flag false":  {host(" allow_weak_crypto = nil", " permitted_enctypes = aes256-cts arcfour-hmac-exp"), registry.DistroDebian, "1.19.2", ruleKrb5Weak, finding.ResultPass, ""},
		"flag true, no weak type": {host(" allow_weak_crypto = true"), registry.DistroDebian, "1.19.2", ruleKrb5Weak, finding.ResultPass, ""},
		"flag true, weak named": {host(" allow_weak_crypto = Yes", " permitted_enctypes = aes256-cts rc4-hmac-exp des3-cbc-raw"), registry.DistroDebian, "1.19.2", ruleKrb5Weak, finding.ResultFail,
			"[libdefaults] allow_weak_crypto value=Yes line=/etc/krb5.conf:2|[libdefaults] permitted_enctypes value=aes256-cts rc4-hmac-exp des3-cbc-raw line=/etc/krb5.conf:3 description=in force: arcfour-hmac-exp, des3-cbc-raw"},
		"flag true, weak triple DES on a Red Hat build": {host(" allow_weak_crypto = 1", " permitted_enctypes = aes256-cts des3-cbc-raw"), registry.DistroRHEL, "1.21.1", ruleKrb5Weak, finding.ResultPass, ""},
		"flag the library refuses":                      {host(" allow_weak_crypto = f"), registry.DistroDebian, "1.19.2", ruleKrb5Weak, finding.ResultUnknown, "which the library refuses"},
		"flag the library refuses, other rule":          {host(" allow_weak_crypto = maybe"), registry.DistroDebian, "1.19.2", ruleKrb5Deprecated, finding.ResultUnknown, "which the library refuses"},
		"configuration the library refuses":             {host("include /etc/missing"), registry.DistroDebian, "1.19.2", ruleKrb5Deprecated, finding.ResultUnknown, "does not start with this configuration"},
	}
	for name, c := range cases {
		got := runKerberos(c.fsys, c.family, c.release)[c.key]
		var subjects []string
		for _, e := range got.Evidence {
			subjects = append(subjects, strings.TrimSpace(e.Subject+" "+factText(e)))
		}
		shown := got.Reason
		if got.Result == finding.ResultFail {
			shown = strings.Join(subjects, "|")
		}
		if got.Result != c.want || !strings.Contains(shown, c.text) || c.want == finding.ResultFail && shown != c.text {
			t.Errorf("%s: %s %q, want %s %q", name, got.Result, shown, c.want, c.text)
		}
	}
}

// A keytab, at its default path or the one the configuration names, and an
// SSSD domain authenticating with krb5 each show use, and are recorded.
func TestRecordKerberosUse(t *testing.T) {
	conf := "[libdefaults]\n permitted_enctypes = aes256-cts\n"
	named := runKerberos(fstest.MapFS{
		"etc/krb5.conf":        text(conf + " default_keytab_name = FILE:/etc/krb5/host.keytab\n"),
		"etc/krb5/host.keytab": text("keytab"),
	}, registry.DistroDebian, "1.19.2")
	if named[ruleKrb5Deprecated].Result != finding.ResultPass || named[ruleKrb5Present].Evidence[0].Subject != "/etc/krb5/host.keytab" {
		t.Errorf("keytab the configuration names: %+v %+v", named[ruleKrb5Deprecated], named[ruleKrb5Present])
	}

	sssd := runKerberos(fstest.MapFS{
		"etc/krb5.conf":      text(conf),
		"etc/sssd/sssd.conf": sssdFile("[sssd]\ndomains = corp\n[domain/corp]\nid_provider = ldap\nauth_provider = krb5\n"),
	}, registry.DistroDebian, "1.19.2")
	present := sssd[ruleKrb5Present]
	if sssd[ruleKrb5Deprecated].Result != finding.ResultPass || len(present.Evidence) != 1 ||
		present.Evidence[0].Subject+" "+factText(present.Evidence[0]) != "[domain/corp] auth_provider value=krb5 line=/etc/sssd/sssd.conf:5" {
		t.Errorf("SSSD domain authenticating with krb5: %+v %+v", sssd[ruleKrb5Deprecated], present)
	}

	ldapOnly := runKerberos(fstest.MapFS{
		"etc/krb5.conf":      text(conf),
		"etc/sssd/sssd.conf": sssdFile("[sssd]\ndomains = corp\n[domain/corp]\nid_provider = ldap\n"),
	}, registry.DistroDebian, "1.19.2")
	if ldapOnly[ruleKrb5Deprecated].Result != finding.ResultNotApplicable {
		t.Errorf("SSSD domain not using krb5: %+v", ldapOnly[ruleKrb5Deprecated])
	}
}

// The vendor copy of krb5.conf is presence on the families whose library
// reads it.
func TestKerberosVendorConfigIsPresence(t *testing.T) {
	fsys := fstest.MapFS{"usr/etc/krb5.conf": text("[libdefaults]\n")}
	for family, want := range map[registry.Distro]bool{registry.DistroSUSE: true, registry.DistroAlpine: true, registry.DistroDebian: false} {
		linux := registry.OSContext{Platform: registry.PlatformLinux, Families: []registry.Distro{family, registry.DistroGeneric}}
		r := &report{osCtx: linux, index: make(map[registry.FindingKey]int)}
		recordDirectoryClients(r, fsys, directoryClients(linux.Families), nssWiring{}, readPAMStack(fsys, pamLayoutFor(nil), nil))
		for _, c := range r.finish().Conditions {
			if c.Key == string(ruleKrb5Present) && (len(c.Evidence) == 1) != want {
				t.Errorf("%s: %+v", family, c)
			}
		}
	}
}

// The release is the last word klist -V prints.
func TestParseKrb5Release(t *testing.T) {
	v, err := parseKrb5Release("Kerberos 5 version 1.19.2\n")
	if err != nil || v.major != 1 || v.minor != 19 || v.text != "1.19.2" {
		t.Errorf("%+v %v", v, err)
	}
	for _, output := range []string{"", "Kerberos 5", "version one.two"} {
		if _, err := parseKrb5Release(output); err == nil {
			t.Errorf("%q was read as a release", output)
		}
	}
}
