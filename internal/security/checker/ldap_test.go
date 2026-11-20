// internal/security/checker/ldap_test.go

package checker

import (
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
)

// unreadable is a file system whose files exist and cannot be read, as
// /etc/nslcd.conf is to an unprivileged caller.
type unreadable struct{ fstest.MapFS }

func (unreadable) ReadFile(string) ([]byte, error) { return nil, fs.ErrPermission }

// ownerOf returns the owner a test file system records for a file.
func ownerOf(info fs.FileInfo) (uint32, uint32, bool) {
	o, ok := info.Sys().(owned)
	return o.uid, o.gid, ok
}

// nslcdHost is a host whose nslcd.conf holds lines, owned by root and closed
// to everyone else, with the name service switch and a PAM rule naming nslcd
// where asked.
func nslcdHost(nss, pam bool, lines ...string) fstest.MapFS {
	fsys := fstest.MapFS{nslcdConfFile: sssdFile(strings.Join(lines, "\n") + "\n")}
	if nss {
		fsys["etc/nsswitch.conf"] = text("passwd: files ldap\n")
	}
	if pam {
		fsys["etc/pam.d/login"] = text("auth required pam_ldap.so\n")
	}
	return fsys
}

// conditions returns what r recorded, by rule.
func conditions(r *report) map[registry.FindingKey]finding.Condition {
	got := map[registry.FindingKey]finding.Condition{}
	for _, c := range r.finish().Conditions {
		got[registry.FindingKey(c.Key)] = c
	}
	return got
}

// runNslcd judges the nslcd configuration in fsys, with the wiring read from
// its name service switch and PAM stack.
func runNslcd(fsys fs.FS) map[registry.FindingKey]finding.Condition {
	linux := registry.OSContext{Platform: registry.PlatformLinux, Families: []registry.Distro{registry.DistroDebian, registry.DistroGeneric}}
	clients := directoryClients(linux.Families)
	nss, _ := readNSSWiring(fsys, linux.Families)
	stack := readPAMStack(fsys, pamLayoutFor(linux.Families), clientModules(clients))
	nslcd := clientFor(clients, ruleNslcdPresent)
	r := &report{osCtx: linux, index: make(map[registry.FindingKey]int)}
	recordNslcd(r, fsys, ownerOf, nslcd.lookups(nss), nslcd.logins(stack))
	return conditions(r)
}

// runOpenLDAP judges the OpenLDAP client configuration at path in fsys.
func runOpenLDAP(fsys fs.FS, path string) finding.Condition {
	linux := registry.OSContext{Platform: registry.PlatformLinux, Families: []registry.Distro{registry.DistroGeneric}}
	r := &report{osCtx: linux, index: make(map[registry.FindingKey]int)}
	recordOpenLDAP(r, fsys, path)
	return conditions(r)[ruleLDAPCertificate]
}

// outcome is a condition's result with the text that explains it: the
// evidence of a failure, and the reason of anything else.
func outcome(c finding.Condition) (finding.Result, string) {
	if c.Result != finding.ResultFail {
		return c.Result, c.Reason
	}
	subjects := make([]string, 0, len(c.Evidence))
	for _, e := range c.Evidence {
		subjects = append(subjects, strings.TrimSpace(e.Subject+" "+factText(e)))
	}
	return c.Result, strings.Join(subjects, "|")
}

// An option's name is read without regard to case, a comment begins a line,
// and blanks, tabs and a carriage return separate a name from its value.
func TestReadLDAPOptions(t *testing.T) {
	got := readLDAPOptions("etc/ldap.conf", []byte("# comment\n  # not a comment\nURI ldap://a\n\tTls_ReqCert\tnever\r\nbindpw two  words\n\nuri ldaps://b\n"))
	want := ldapOptions{
		"#":           {{value: "not a comment", file: "etc/ldap.conf", line: 2}},
		"uri":         {{value: "ldap://a", file: "etc/ldap.conf", line: 3}, {value: "ldaps://b", file: "etc/ldap.conf", line: 7}},
		"tls_reqcert": {{value: "never", file: "etc/ldap.conf", line: 4}},
		"bindpw":      {{value: "two words", file: "etc/ldap.conf", line: 5}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("options %v, want %v", got, want)
	}
	if set, ok := got.last("uri"); !ok || set.line != 7 {
		t.Errorf("last uri %+v", set)
	}
	if _, ok := got.last("ssl"); ok {
		t.Error("an option no line sets was reported set")
	}
}

// What nslcd was seen to refuse is recorded in the order of the lines, and
// what it accepts is not.
func TestReadNslcdConfigRefused(t *testing.T) {
	read := func(lines ...string) []string {
		config, err := readNslcdConfig(nslcdHost(false, false, lines...))
		if err != nil {
			t.Fatal(err)
		}
		return config.refused
	}

	got := read("  # note", "uri", "ssl", "ssl on off", `tls_reqcert "never"`, "ignorecase maybe", "tls_reqcert true")
	want := []string{
		"/etc/nslcd.conf:1 is a comment after blanks, which nslcd reads as a keyword",
		"/etc/nslcd.conf:2 names no server",
		"/etc/nslcd.conf:3 gives ssl 0 values where nslcd takes one",
		"/etc/nslcd.conf:4 gives ssl 2 values where nslcd takes one",
		`/etc/nslcd.conf:5 sets tls_reqcert to "\"never\"", which nslcd does not accept`,
		`/etc/nslcd.conf:6 sets ignorecase to "maybe", which nslcd does not accept`,
		`/etc/nslcd.conf:7 sets tls_reqcert to "true", which nslcd does not accept`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("refused\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	if got := read("# only a comment"); !reflect.DeepEqual(got, []string{"/etc/nslcd.conf names no uri"}) {
		t.Errorf("a file naming no server: %v", got)
	}
	accepted := read("# packaged", "uid nslcd", "URI ldap://a/ ldaps://b/", "ssl StartTLS", "ssl 1", "ssl no",
		"tls_reqcert HARD", "tls_reqcert yes", "ignorecase 0", "bindpw two words", "base dc=example,dc=com")
	if len(accepted) != 0 {
		t.Errorf("accepted lines were refused: %v", accepted)
	}
}

// A server is reached over TLS, on the host itself, or in clear unless the
// client asks for TLS, by the URI naming it.
func TestLDAPReach(t *testing.T) {
	cases := map[string]ldapReach{
		"ldaps://dir.example.com/":      ldapOverTLS,
		"LDAPS://dir.example.com":       ldapOverTLS,
		"ldapi:///":                     ldapOnHost,
		"ldapi://%2fvar%2frun%2fldapi/": ldapOnHost,
		"ldap:///":                      ldapOnHost,
		"ldap://127.0.0.1/":             ldapOnHost,
		"ldap://127.8.9.10:389":         ldapOnHost,
		"LDAP://LocalHost:389/dc=x":     ldapOnHost,
		"ldap://[::1]:389/":             ldapOnHost,
		"ldap://dir.example.com/":       ldapInClear,
		"LDAP://10.0.0.5:389":           ldapInClear,
		"ldap://[2001:db8::1]/":         ldapInClear,
		"ldap://localhost.example.com/": ldapInClear,
		"ldap://dir.example.com?base":   ldapInClear,
		"http://dir.example.com/":       ldapUnrecognised,
		"dir.example.com":               ldapUnrecognised,
		`"ldaps://dir.example.com/"`:    ldapUnrecognised,
	}
	for uri, want := range cases {
		if got := ldapReachOf(uri); got != want {
			t.Errorf("%s: reach %d, want %d", uri, got, want)
		}
	}

	lookups := map[string]ldapReach{
		"DNS":                    ldapInClear,
		"dns:example.com":        ldapInClear,
		"DNSLDAPS":               ldapOverTLS,
		"DNSLDAPS:example.com":   ldapOverTLS,
		"ldap://127.0.0.1/":      ldapOnHost,
		"ldap://dns.example.com": ldapInClear,
		"DNSX":                   ldapUnrecognised,
	}
	for server, want := range lookups {
		if got := nslcdReach(server); got != want {
			t.Errorf("nslcd %s: reach %d, want %d", server, got, want)
		}
	}
}

// Each rule on what nslcd.conf sets is concluded where the host is wired to
// nslcd, from the settings in force as nslcd was seen to read them.
func TestRecordNslcdRules(t *testing.T) {
	const (
		nssLine = "passwd line=/etc/nsswitch.conf:1 value=files ldap"
		pamRule = "auth pam_ldap.so line=/etc/pam.d/login:1 services=login"
		away    = "uri ldap://dir.example.com/"
	)
	cases := map[string]struct {
		fsys fstest.MapFS
		key  registry.FindingKey
		want finding.Result
		text string
	}{
		"lookups in clear": {nslcdHost(true, false, away), ruleNslcdLookups, finding.ResultFail,
			nssLine + "|ssl state=not set|uri value=ldap://dir.example.com/ line=/etc/nslcd.conf:1"},
		"lookups wired, logins not": {nslcdHost(true, false, away), ruleNslcdLogins, finding.ResultNotApplicable, "no PAM rule names pam_ldap.so"},
		"logins in clear with ssl off": {nslcdHost(false, true, away, "ssl off"), ruleNslcdLogins, finding.ResultFail,
			pamRule + "|ssl value=off line=/etc/nslcd.conf:2|uri value=ldap://dir.example.com/ line=/etc/nslcd.conf:1"},
		"logins wired, lookups not": {nslcdHost(false, true, away), ruleNslcdLookups, finding.ResultNotApplicable, "the name service switch does not name ldap"},
		"start_tls":                 {nslcdHost(true, true, away, "ssl START_TLS"), ruleNslcdLookups, finding.ResultPass, ""},
		"ssl yes":                   {nslcdHost(true, true, away, "ssl yes"), ruleNslcdLogins, finding.ResultPass, ""},
		"off after start_tls":       {nslcdHost(true, true, away, "ssl start_tls", "ssl off"), ruleNslcdLogins, finding.ResultPass, ""},
		"off before start_tls":      {nslcdHost(true, true, away, "ssl off", "ssl starttls"), ruleNslcdLookups, finding.ResultPass, ""},
		"ldaps server":              {nslcdHost(true, true, "uri ldaps://dir.example.com/"), ruleNslcdLookups, finding.ResultPass, ""},
		"second server on the line in clear": {nslcdHost(true, false, "uri ldaps://a.example.com/ ldap://b.example.com/"), ruleNslcdLookups, finding.ResultFail,
			nssLine + "|ssl state=not set|uri value=ldap://b.example.com/ line=/etc/nslcd.conf:1"},
		"second uri line in clear": {nslcdHost(true, false, "uri ldaps://a.example.com/", "URI LDAP://b.example.com/"), ruleNslcdLookups, finding.ResultFail,
			nssLine + "|ssl state=not set|uri value=LDAP://b.example.com/ line=/etc/nslcd.conf:2"},
		"packaged server on the host":  {nslcdHost(true, true, "uri ldap://127.0.0.1/"), ruleNslcdLogins, finding.ResultPass, ""},
		"socket and loopback servers":  {nslcdHost(true, true, "uri ldapi:/// ldap://localhost/ ldap://[::1]/ ldap:///"), ruleNslcdLookups, finding.ResultPass, ""},
		"loopback beside another host": {nslcdHost(true, true, "uri ldap://127.0.0.1/", "uri ldap://dir.example.com/"), ruleNslcdLookups, finding.ResultFail, nssLine + "|ssl state=not set|uri value=ldap://dir.example.com/ line=/etc/nslcd.conf:2"},
		"servers found in DNS": {nslcdHost(true, false, "uri dns:example.com"), ruleNslcdLookups, finding.ResultFail,
			nssLine + "|ssl state=not set|uri value=dns:example.com line=/etc/nslcd.conf:1"},
		"servers found in DNS for ldaps": {nslcdHost(true, true, "uri DNSLDAPS"), ruleNslcdLookups, finding.ResultPass, ""},
		"server of no known form":        {nslcdHost(true, true, "uri dir.example.com"), ruleNslcdLogins, finding.ResultUnknown, `/etc/nslcd.conf:1 names "dir.example.com", which is not a server nslcd.conf(5) describes`},
		"refused value":                  {nslcdHost(true, true, away, "ssl sometimes"), ruleNslcdLookups, finding.ResultUnknown, `/etc/nslcd.conf:2 sets ssl to "sometimes", which nslcd does not accept, so nslcd does not start with this configuration`},
		"not wired":                      {nslcdHost(false, false, away, "tls_reqcert never", "ignorecase yes"), ruleNslcdLookups, finding.ResultNotApplicable, "the host is not seen to use nslcd"},

		"certificate unchecked on ldaps": {nslcdHost(true, false, "uri ldaps://dir.example.com/", "tls_reqcert never"), ruleNslcdCertificate, finding.ResultFail,
			"tls_reqcert value=never line=/etc/nslcd.conf:2|uri value=ldaps://dir.example.com/ line=/etc/nslcd.conf:1"},
		"certificate unchecked on start_tls": {nslcdHost(false, true, away, "ssl start_tls", "tls_reqcert no"), ruleNslcdCertificate, finding.ResultFail,
			"tls_reqcert value=no line=/etc/nslcd.conf:3|ssl value=start_tls line=/etc/nslcd.conf:2"},
		"demand then never": {nslcdHost(true, false, "uri ldaps://dir.example.com/", "tls_reqcert demand", "TLS_REQCERT Allow"), ruleNslcdCertificate, finding.ResultFail,
			"tls_reqcert value=Allow line=/etc/nslcd.conf:3|uri value=ldaps://dir.example.com/ line=/etc/nslcd.conf:1"},
		"never then demand":          {nslcdHost(true, false, "uri ldaps://dir.example.com/", "tls_reqcert never", "tls_reqcert demand"), ruleNslcdCertificate, finding.ResultPass, ""},
		"certificate check unset":    {nslcdHost(true, false, "uri ldaps://dir.example.com/"), ruleNslcdCertificate, finding.ResultPass, ""},
		"certificate check yes":      {nslcdHost(true, false, "uri ldaps://dir.example.com/", "tls_reqcert yes"), ruleNslcdCertificate, finding.ResultPass, ""},
		"never with no TLS in use":   {nslcdHost(true, false, away, "tls_reqcert never"), ruleNslcdCertificate, finding.ResultPass, ""},
		"never, server of no form":   {nslcdHost(true, false, "uri dir.example.com", "tls_reqcert never"), ruleNslcdCertificate, finding.ResultUnknown, "how nslcd connects is not known"},
		"certificate rule not wired": {nslcdHost(false, false, "uri ldaps://dir.example.com/", "tls_reqcert never"), ruleNslcdCertificate, finding.ResultNotApplicable, "the host is not seen to use nslcd"},

		"ignorecase yes": {nslcdHost(false, true, "uri ldap://127.0.0.1/", "ignorecase YES"), ruleNslcdCase, finding.ResultFail,
			"ignorecase value=YES line=/etc/nslcd.conf:2"},
		"ignorecase yes then no":            {nslcdHost(true, false, "uri ldap://127.0.0.1/", "ignorecase yes", "ignorecase no"), ruleNslcdCase, finding.ResultPass, ""},
		"ignorecase no then on":             {nslcdHost(true, false, "uri ldap://127.0.0.1/", "ignorecase no", "ignorecase on"), ruleNslcdCase, finding.ResultFail, "ignorecase value=on line=/etc/nslcd.conf:3"},
		"ignorecase unset":                  {nslcdHost(true, false, "uri ldap://127.0.0.1/"), ruleNslcdCase, finding.ResultPass, ""},
		"ignorecase, server of no form":     {nslcdHost(true, false, "uri dir.example.com"), ruleNslcdCase, finding.ResultPass, ""},
		"ignorecase rule not wired":         {nslcdHost(false, false, "uri ldap://127.0.0.1/", "ignorecase yes"), ruleNslcdCase, finding.ResultNotApplicable, "the host is not seen to use nslcd"},
		"ignorecase in a refused file":      {nslcdHost(true, false, "ignorecase yes"), ruleNslcdCase, finding.ResultUnknown, "/etc/nslcd.conf names no uri, so nslcd does not start"},
		"no password in an unwired file":    {nslcdHost(false, false, "uri ldap://127.0.0.1/"), ruleNslcdReadable, finding.ResultNotApplicable, "/etc/nslcd.conf sets neither bindpw nor rootpwmodpw"},
		"password in a file closed to all":  {nslcdHost(false, false, "uri ldap://127.0.0.1/", "bindpw opensesame"), ruleNslcdReadable, finding.ResultPass, ""},
		"password rule in a refused file":   {nslcdHost(true, true, "bindpw opensesame"), ruleNslcdReadable, finding.ResultPass, ""},
		"no configuration":                  {fstest.MapFS{"etc/nsswitch.conf": text("passwd: files ldap\n")}, ruleNslcdLookups, finding.ResultNotChecked, "/etc/nslcd.conf is not present"},
		"no configuration, password rule":   {fstest.MapFS{}, ruleNslcdReadable, finding.ResultNotChecked, "/etc/nslcd.conf is not present"},
		"no configuration, ignorecase rule": {fstest.MapFS{}, ruleNslcdCase, finding.ResultNotChecked, "/etc/nslcd.conf is not present"},
	}
	for name, c := range cases {
		got, text := outcome(runNslcd(c.fsys)[c.key])
		if got != c.want || !strings.Contains(text, c.text) || c.want == finding.ResultFail && text != c.text {
			t.Errorf("%s: %s %q, want %s %q", name, got, text, c.want, c.text)
		}
	}
}

// A file an unprivileged caller cannot read is an error for every rule, not
// a host with no configuration.
func TestRecordNslcdUnreadable(t *testing.T) {
	got := runNslcd(unreadable{nslcdHost(true, true, "uri ldap://dir.example.com/")})
	for _, key := range append([]registry.FindingKey{ruleNslcdReadable}, nslcdUseRules...) {
		if c := got[key]; c.Result != finding.ResultError || !strings.Contains(c.Reason, fs.ErrPermission.Error()) {
			t.Errorf("%s: %s %q", key, c.Result, c.Reason)
		}
	}
}

// A Debian family host with libpam-ldapd installed and nothing configured has
// the packaged file, readable by the nslcd group, and PAM rules naming
// pam_ldap.so. It fails no rule.
func TestRecordNslcdAsPackaged(t *testing.T) {
	fsys := nslcdHost(false, true, "uid nslcd", "gid nslcd", "uri ldap://127.0.0.1/", "base dc=example,dc=net", "#binddn cn=x", "#bindpw x", "#ssl off", "#tls_reqcert never")
	fsys[nslcdConfFile].Mode = 0o640
	fsys[nslcdConfFile].Sys = owned{gid: 114}
	want := map[registry.FindingKey]finding.Result{
		ruleNslcdLookups:     finding.ResultNotApplicable,
		ruleNslcdLogins:      finding.ResultPass,
		ruleNslcdCertificate: finding.ResultPass,
		ruleNslcdCase:        finding.ResultPass,
		ruleNslcdReadable:    finding.ResultNotApplicable,
	}
	got := runNslcd(fsys)
	for key, result := range want {
		if got[key].Result != result {
			t.Errorf("%s: %s %q, want %s", key, got[key].Result, got[key].Reason, result)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%d rules concluded, want %d", len(got), len(want))
	}
}

// A password in nslcd.conf is judged for who can read the file, whether or
// not the host is wired to nslcd, and is not recorded.
func TestRecordNslcdPassword(t *testing.T) {
	const held = "opensesame"
	expected := "expected=owned by root, with no access for its group or others"
	cases := map[string]struct {
		mode  fs.FileMode
		sys   any
		lines []string
		want  finding.Result
		text  string
	}{
		"readable by the nslcd group, as the Debian family packages it": {0o640, owned{gid: 114}, []string{"uri ldap://a/", "bindpw " + held}, finding.ResultFail,
			"/etc/nslcd.conf mode=-rw-r----- uid=0 gid=114 " + expected + "|bindpw line=/etc/nslcd.conf:2"},
		"readable by everyone, as Arch packages it": {0o644, owned{}, []string{"uri ldap://a/", "binddn cn=x", "BindPW " + held}, finding.ResultFail,
			"/etc/nslcd.conf mode=-rw-r--r-- uid=0 gid=0 " + expected + "|bindpw line=/etc/nslcd.conf:3"},
		"readable by the root group": {0o640, owned{}, []string{"rootpwmodpw " + held, "bindpw " + held}, finding.ResultFail,
			"/etc/nslcd.conf mode=-rw-r----- uid=0 gid=0 " + expected + "|bindpw line=/etc/nslcd.conf:2|rootpwmodpw line=/etc/nslcd.conf:1"},
		"owned by the nslcd account": {0o600, owned{uid: 114}, []string{"bindpw " + held}, finding.ResultFail,
			"/etc/nslcd.conf mode=-rw------- uid=114 gid=0 " + expected + "|bindpw line=/etc/nslcd.conf:1"},
		"root alone":              {0o600, owned{}, []string{"bindpw " + held}, finding.ResultPass, ""},
		"no password, world read": {0o644, owned{}, []string{"uri ldap://a/", "#bindpw " + held}, finding.ResultNotApplicable, "sets neither bindpw nor rootpwmodpw"},
		"owner not recorded":      {0o644, nil, []string{"bindpw " + held}, finding.ResultError, "ownership could not be determined"},
	}
	for name, c := range cases {
		fsys := nslcdHost(false, false, c.lines...)
		fsys[nslcdConfFile].Mode = c.mode
		fsys[nslcdConfFile].Sys = c.sys
		condition := runNslcd(fsys)[ruleNslcdReadable]
		got, text := outcome(condition)
		if got != c.want || !strings.Contains(text, c.text) || c.want == finding.ResultFail && text != c.text {
			t.Errorf("%s: %s %q, want %s %q", name, got, text, c.want, c.text)
		}
		if strings.Contains(text+condition.Reason, held) {
			t.Errorf("%s: the password is in what was recorded: %q", name, text)
		}
	}
}

// The OpenLDAP client is judged where its file names a server, by the last
// TLS_REQCERT the library accepts.
func TestRecordOpenLDAP(t *testing.T) {
	const path = "/etc/ldap/ldap.conf"
	file := func(lines ...string) fstest.MapFS {
		return fstest.MapFS{"etc/ldap/ldap.conf": text(strings.Join(lines, "\n") + "\n")}
	}
	cases := map[string]struct {
		fsys fs.FS
		path string
		want finding.Result
		text string
	}{
		"never": {file("URI ldaps://dir.example.com", "TLS_REQCERT never"), path, finding.ResultFail,
			"TLS_REQCERT value=never line=/etc/ldap/ldap.conf:2|URI value=ldaps://dir.example.com line=/etc/ldap/ldap.conf:1"},
		"allow, in lower case, for a HOST": {file("host dir.example.com", "tls_reqcert Allow"), path, finding.ResultFail,
			"TLS_REQCERT value=Allow line=/etc/ldap/ldap.conf:2|HOST value=dir.example.com line=/etc/ldap/ldap.conf:1"},
		"demand then never": {file("URI ldap://a", "TLS_REQCERT demand", "TLS_REQCERT never"), path, finding.ResultFail,
			"TLS_REQCERT value=never line=/etc/ldap/ldap.conf:3|URI value=ldap://a line=/etc/ldap/ldap.conf:1"},
		"never then a value the library ignores": {file("URI ldap://a", "TLS_REQCERT never", "TLS_REQCERT sometimes"), path, finding.ResultFail,
			"TLS_REQCERT value=never line=/etc/ldap/ldap.conf:2|URI value=ldap://a line=/etc/ldap/ldap.conf:1"},
		"never then demand":           {file("URI ldap://a", "TLS_REQCERT never", "TLS_REQCERT demand"), path, finding.ResultPass, ""},
		"never with a comment after":  {file("URI ldap://a", "TLS_REQCERT never # for now"), path, finding.ResultPass, ""},
		"no, which the library drops": {file("URI ldap://a", "TLS_REQCERT no"), path, finding.ResultPass, ""},
		"try":                         {file("URI ldap://a", "TLS_REQCERT try"), path, finding.ResultPass, ""},
		"unset":                       {file("URI ldap://a"), path, finding.ResultPass, ""},
		"packaged, naming no server":  {file("#URI ldap://a", "TLS_CACERT /etc/ssl/certs/ca-certificates.crt", "TLS_REQCERT never"), path, finding.ResultNotApplicable, "/etc/ldap/ldap.conf sets neither URI nor HOST"},
		"no file":                     {fstest.MapFS{}, path, finding.ResultNotChecked, "/etc/ldap/ldap.conf is not present"},
		"path not established":        {file("URI ldap://a", "TLS_REQCERT never"), "", finding.ResultNotChecked, "not established for this distribution"},
		"unreadable":                  {unreadable{file("URI ldap://a")}, path, finding.ResultError, fs.ErrPermission.Error()},
	}
	for name, c := range cases {
		got, text := outcome(runOpenLDAP(c.fsys, c.path))
		if got != c.want || !strings.Contains(text, c.text) || c.want == finding.ResultFail && text != c.text {
			t.Errorf("%s: %s %q, want %s %q", name, got, text, c.want, c.text)
		}
	}
}

// The clients the rules judge are among those recorded, and a key recording
// none is a defect in the checker.
func TestClientFor(t *testing.T) {
	clients := directoryClients([]registry.Distro{registry.DistroRHEL})
	if c := clientFor(clients, ruleNslcdPresent); c.nss != "ldap" || c.module != "pam_ldap.so" || c.path != "/etc/nslcd.conf" {
		t.Errorf("nslcd client: %+v", c)
	}
	if c := clientFor(clients, ruleLDAPPresent); c.path != "/etc/openldap/ldap.conf" {
		t.Errorf("OpenLDAP client: %+v", c)
	}
	defer func() {
		if recover() == nil {
			t.Error("a key recording no client was accepted")
		}
	}()
	clientFor(clients, "users.no_such_client")
}

// A file's group and others are judged against root alone, or against root
// and a service account.
func TestFileExcess(t *testing.T) {
	service := localAccount{uid: 114, gid: 120, user: true, group: true}
	cases := map[string]struct {
		perm        fs.FileMode
		uid, gid    uint32
		service     localAccount
		read, write bool
	}{
		"root alone":                         {0o600, 0, 0, localAccount{}, false, false},
		"group read, root alone allowed":     {0o640, 0, 120, localAccount{}, true, false},
		"group read by the service group":    {0o640, 0, 120, service, false, false},
		"group write by another group":       {0o660, 0, 5, service, true, true},
		"others read":                        {0o604, 0, 120, service, true, false},
		"others write":                       {0o602, 114, 120, service, false, true},
		"owned by the service account":       {0o600, 114, 0, service, false, false},
		"owned by another account":           {0o600, 1000, 0, service, true, true},
		"owned by a service account unasked": {0o600, 114, 0, localAccount{}, true, true},
	}
	for name, c := range cases {
		if read, write := fileExcess(c.perm, c.uid, c.gid, c.service); read != c.read || write != c.write {
			t.Errorf("%s: read %v write %v, want %v %v", name, read, write, c.read, c.write)
		}
	}

	fsys := fstest.MapFS{
		"etc/passwd": text("root:x:0:0::/root:/bin/sh\nnslcd:x:114:120::/run/nslcd:/usr/sbin/nologin\n"),
		"etc/group":  text("root:x:0:\nnslcd:x:120:\n"),
	}
	if got := lookupLocalAccount(fsys, "nslcd"); got != service {
		t.Errorf("nslcd account %+v, want %+v", got, service)
	}
	if got := lookupLocalAccount(fsys, "sssd"); got != (localAccount{}) {
		t.Errorf("an account the host does not have: %+v", got)
	}
}

// The rules are reported in one order whether or not the file is present:
// what the connection carries, then the password the file holds.
func TestRecordNslcdOrder(t *testing.T) {
	want := []string{
		string(ruleNslcdLookups), string(ruleNslcdLogins), string(ruleNslcdCertificate), string(ruleNslcdCase), string(ruleNslcdReadable),
	}
	for name, fsys := range map[string]fstest.MapFS{
		"no configuration": {},
		"in use":           nslcdHost(true, true, "uri ldap://dir.example.com/", "bindpw opensesame"),
	} {
		linux := registry.OSContext{Platform: registry.PlatformLinux, Families: []registry.Distro{registry.DistroGeneric}}
		r := &report{osCtx: linux, index: make(map[registry.FindingKey]int)}
		lookups := []finding.Evidence{evidence(finding.KindNSSEntry, "passwd", fact(finding.FactLine, "/etc/nsswitch.conf:1"))}
		recordNslcd(r, fsys, ownerOf, lookups, nil)
		var got []string
		for _, c := range r.finish().Conditions {
			got = append(got, c.Key)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: order %v, want %v", name, got, want)
		}
	}
}
