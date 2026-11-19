// internal/security/checker/sssd_test.go

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

// owned is the owner and group a test file system records for a file.
type owned struct{ uid, gid uint32 }

// sssdFile is a configuration file owned by root and closed to everyone else.
func sssdFile(content string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte(content), Mode: 0o600, Sys: owned{}}
}

// runSSSD judges the SSSD configuration in fsys on a host with the given
// release installed, or with none readable when release is empty.
func runSSSD(fsys fs.FS, release string) map[registry.FindingKey]finding.Condition {
	linux := registry.OSContext{Platform: registry.PlatformLinux, Families: []registry.Distro{registry.DistroGeneric}}
	r := &report{osCtx: linux, index: make(map[registry.FindingKey]int)}
	config, err := readSSSDConfig(fsys)
	recordSSSD(r, fsys, sssdHost{
		version: func() (sssdVersion, error) {
			if release == "" {
				return sssdVersion{}, errors.New("sssd is not installed")
			}
			return parseSSSDVersion(release)
		},
		owner: func(info fs.FileInfo) (uint32, uint32, bool) {
			o, ok := info.Sys().(owned)
			return o.uid, o.gid, ok
		},
	}, config, err)
	got := map[registry.FindingKey]finding.Condition{}
	for _, c := range r.finish().Conditions {
		got[registry.FindingKey(c.Key)] = c
	}
	return got
}

// A snippet overrides sssd.conf and a later snippet an earlier one, and where
// two snippets disagree and a locale would order their names differently from
// their bytes, which is in force is not known.
func TestReadSSSDConfig(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/sssd/sssd.conf":             sssdFile("# comment\n; comment\n[sssd]\ndomains = corp\n[domain/corp]\ncache_credentials = true\nldap_uri = ldap://a # kept\n"),
		"etc/sssd/conf.d/10-first.conf":  sssdFile("[domain/corp]\ncache_credentials = false\nkrb5_validate = false\n"),
		"etc/sssd/conf.d/20-second.conf": sssdFile("[domain/corp]\ncache_credentials = true\n"),
		"etc/sssd/conf.d/B.conf":         sssdFile("[domain/corp]\nkrb5_validate = true\n"),
		"etc/sssd/conf.d/a.conf":         sssdFile("[domain/corp]\nkrb5_validate = false\n"),
		"etc/sssd/conf.d/.hidden.conf":   sssdFile("[domain/corp]\ncache_credentials = false\n"),
		"etc/sssd/conf.d/notes.txt":      sssdFile("[domain/corp]\ncache_credentials = false\n"),
	}
	config, err := readSSSDConfig(fsys)
	if err != nil {
		t.Fatal(err)
	}
	wantFiles := []string{"etc/sssd/sssd.conf", "etc/sssd/conf.d/10-first.conf", "etc/sssd/conf.d/20-second.conf", "etc/sssd/conf.d/B.conf", "etc/sssd/conf.d/a.conf"}
	if !reflect.DeepEqual(config.files, wantFiles) {
		t.Errorf("files %v, want %v", config.files, wantFiles)
	}
	if set, _ := config.get("domain/corp", "cache_credentials"); set.value != "true" || set.file != "etc/sssd/conf.d/20-second.conf" || set.line != 2 {
		t.Errorf("the later snippet is not in force: %+v", set)
	}
	if config.undecided("domain/corp", "cache_credentials") {
		t.Error("snippets whose names order the same way in any locale were reported undecided")
	}
	if !config.undecided("domain/corp", "krb5_validate") {
		t.Error("B.conf and a.conf disagree and a locale orders them the other way, which was not reported")
	}
	if set, _ := config.get("domain/corp", "ldap_uri"); set.value != "ldap://a # kept" {
		t.Errorf("an inline comment is not supported, so it is part of the value: %q", set.value)
	}
	if len(config.malformed) != 0 {
		t.Errorf("malformed: %v", config.malformed)
	}

	broken, err := readSSSDConfig(fstest.MapFS{"etc/sssd/sssd.conf": sssdFile("domains = corp\n[sssd]\nnonsense\n")})
	if err != nil || len(broken.malformed) != 2 {
		t.Errorf("a key outside a section and a line that is neither: %v %v", broken.malformed, err)
	}
	if _, err := readSSSDConfig(fstest.MapFS{}); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("no file and no snippet: %v", err)
	}
}

// A domain is served when domains lists it or it sets enabled = true, and not
// when it sets enabled = false or has no section.
func TestSSSDActiveDomains(t *testing.T) {
	config, err := readSSSDConfig(fstest.MapFS{"etc/sssd/sssd.conf": sssdFile(
		"[sssd]\ndomains = listed, off, absent\n" +
			"[domain/listed]\nid_provider = ldap\n" +
			"[domain/off]\nenabled = false\n" +
			"[domain/on]\nenabled = TRUE\n" +
			"[domain/idle]\nid_provider = ldap\n" +
			"[domain/listed/sub]\nenabled = true\n")})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := config.activeDomains(), []string{"listed", "on"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// With no configuration nothing is judged; one that cannot be read is an
// error; one that serves no domain is judged for its files alone.
func TestRecordSSSDWithoutDomains(t *testing.T) {
	for key, c := range runSSSD(fstest.MapFS{"etc/nsswitch.conf": {Data: []byte("passwd: sss\n")}}, "2.9.9") {
		if c.Result != finding.ResultNotChecked || !strings.Contains(c.Reason, "nor a snippet") {
			t.Errorf("no configuration: %s %+v", key, c)
		}
	}
	for key, c := range runSSSD(statFailure{fstest.MapFS{}}, "2.9.9") {
		if c.Result != finding.ResultError || !strings.Contains(c.Reason, fs.ErrPermission.Error()) {
			t.Errorf("unreadable configuration: %s %+v", key, c)
		}
	}

	unused := runSSSD(fstest.MapFS{"etc/sssd/sssd.conf": sssdFile("[sssd]\nservices = nss, pam\n[domain/idle]\ncache_credentials = true\n")}, "2.9.9")
	for _, key := range sssdFileRules {
		if unused[key].Result != finding.ResultPass {
			t.Errorf("unused, root 0600: %s %+v", key, unused[key])
		}
	}
	for _, key := range sssdContentRules {
		if c := unused[key]; c.Result != finding.ResultNotApplicable || !strings.Contains(c.Reason, "serves no domain") {
			t.Errorf("unused: %s %+v", key, c)
		}
	}

	malformed := runSSSD(fstest.MapFS{"etc/sssd/sssd.conf": sssdFile("[sssd]\ndomains = corp\n[domain/corp]\nnonsense\n")}, "2.9.9")
	for _, key := range sssdContentRules {
		if c := malformed[key]; c.Result != finding.ResultUnknown || !strings.Contains(c.Reason, "/etc/sssd/sssd.conf:4") {
			t.Errorf("malformed: %s %+v", key, c)
		}
	}
}

// A file is judged by the manual of the release installed: root alone before
// SSSD 2.10.0, root or the sssd account from it. With the release unknown it
// is judged only where both agree.
func TestRecordSSSDFiles(t *testing.T) {
	accounts := fstest.MapFS{
		"etc/passwd": {Data: []byte("root:x:0:0::/root:/bin/sh\nsssd:x:499:486::/run/sssd:/sbin/nologin\n")},
		"etc/group":  {Data: []byte("root:x:0:\nsssd:x:486:\n")},
	}
	cases := map[string]struct {
		mode               fs.FileMode
		owner              owned
		release            string
		readable, writable finding.Result
	}{
		"root 0600, 2.9.9":                 {0o600, owned{}, "2.9.9", finding.ResultPass, finding.ResultPass},
		"root:sssd 0640, 2.9.9":            {0o640, owned{0, 486}, "2.9.9", finding.ResultFail, finding.ResultPass},
		"root:sssd 0640, 2.10.2":           {0o640, owned{0, 486}, "2.10.2", finding.ResultPass, finding.ResultPass},
		"root:sssd 0640, release unknown":  {0o640, owned{0, 486}, "", finding.ResultUnknown, finding.ResultPass},
		"sssd:sssd 0600, 2.9.9":            {0o600, owned{499, 486}, "2.9.9", finding.ResultFail, finding.ResultFail},
		"sssd:sssd 0600, 2.10.2":           {0o600, owned{499, 486}, "2.10.2", finding.ResultPass, finding.ResultPass},
		"root:users 0640, 2.10.2":          {0o640, owned{0, 100}, "2.10.2", finding.ResultFail, finding.ResultPass},
		"root 0644, release unknown":       {0o644, owned{}, "", finding.ResultFail, finding.ResultPass},
		"root 0666, 2.10.2":                {0o666, owned{}, "2.10.2", finding.ResultFail, finding.ResultFail},
		"another account's 0600, 2.10.2":   {0o600, owned{1000, 1000}, "2.10.2", finding.ResultFail, finding.ResultFail},
		"root 0600, release unknown":       {0o600, owned{}, "", finding.ResultPass, finding.ResultPass},
		"sssd:sssd 0600, release unknown":  {0o600, owned{499, 486}, "", finding.ResultUnknown, finding.ResultUnknown},
		"root:sssd 0660, 3.0.0":            {0o660, owned{0, 486}, "3.0.0", finding.ResultPass, finding.ResultPass},
		"root:sssd 0660, 2.9.9 writable":   {0o660, owned{0, 486}, "2.9.9", finding.ResultFail, finding.ResultFail},
		"root 0600 with no sssd, 2.10.2":   {0o600, owned{}, "2.10.2", finding.ResultPass, finding.ResultPass},
		"root:486 0640 with sssd, 2.10.2 ": {0o640, owned{0, 486}, "2.10.2", finding.ResultPass, finding.ResultPass},
	}
	for name, c := range cases {
		fsys := fstest.MapFS{"etc/sssd/sssd.conf": {Data: []byte("[sssd]\n"), Mode: c.mode, Sys: c.owner}}
		for file, entry := range accounts {
			fsys[file] = entry
		}
		got := runSSSD(fsys, c.release)
		if got[ruleSSSDReadable].Result != c.readable || got[ruleSSSDWritable].Result != c.writable {
			t.Errorf("%s: readable %s, writable %s; want %s, %s", name,
				got[ruleSSSDReadable].Result, got[ruleSSSDWritable].Result, c.readable, c.writable)
		}
	}

	snippet := runSSSD(fstest.MapFS{
		"etc/sssd/sssd.conf":         sssdFile("[sssd]\n"),
		"etc/sssd/conf.d/50-ad.conf": {Data: []byte("[sssd]\n"), Mode: 0o644, Sys: owned{}},
	}, "2.9.9")
	readable := snippet[ruleSSSDReadable]
	if readable.Result != finding.ResultFail || len(readable.Evidence) != 1 || readable.Evidence[0].Subject != "/etc/sssd/conf.d/50-ad.conf" ||
		!strings.Contains(factText(readable.Evidence[0]), "mode=-rw-r--r-- uid=0 gid=0 expected=owned by root, with no access for its group or others version=2.9.9") {
		t.Errorf("a snippet others can read: %+v", readable)
	}
}

// Each content rule is concluded from the domains SSSD serves that it covers.
func TestRecordSSSDRules(t *testing.T) {
	domain := func(lines ...string) fstest.MapFS {
		return fstest.MapFS{"etc/sssd/sssd.conf": sssdFile("[sssd]\ndomains = corp\n[pam]\noffline_credentials_expiration = 3\n[domain/corp]\n" + strings.Join(lines, "\n") + "\n")}
	}
	cases := map[string]struct {
		fsys    fstest.MapFS
		release string
		key     registry.FindingKey
		want    finding.Result
		text    string
	}{
		"start_tls unset before 2.10.0": {domain("id_provider = ldap", "ldap_uri = ldap://a"), "2.9.9", ruleSSSDLDAPClear, finding.ResultFail,
			"[domain/corp] ldap_id_use_start_tls state=not set version=2.9.9|[domain/corp] ldap_uri value=ldap://a line=/etc/sssd/sssd.conf:7|[domain/corp] ldap_backup_uri state=not set"},
		"start_tls unset from 2.10.0":      {domain("id_provider = ldap", "ldap_uri = ldap://a"), "2.10.2", ruleSSSDLDAPClear, finding.ResultPass, ""},
		"start_tls unset, release unknown": {domain("id_provider = ldap", "ldap_uri = ldap://a"), "", ruleSSSDLDAPClear, finding.ResultUnknown, "the release could not be read"},
		"start_tls false from 2.10.0": {domain("id_provider = ldap", "ldap_backup_uri = LDAP://b", "ldap_id_use_start_tls = False"), "2.10.2", ruleSSSDLDAPClear, finding.ResultFail,
			"[domain/corp] ldap_id_use_start_tls value=False line=/etc/sssd/sssd.conf:8 version=2.10.2|[domain/corp] ldap_uri state=not set|[domain/corp] ldap_backup_uri value=LDAP://b line=/etc/sssd/sssd.conf:7"},
		"start_tls true":           {domain("id_provider = ldap", "ldap_uri = ldap://a", "ldap_id_use_start_tls = true"), "2.9.9", ruleSSSDLDAPClear, finding.ResultPass, ""},
		"ldaps servers only":       {domain("id_provider = ldap", "ldap_uri = ldaps://a, ldaps://b"), "2.9.9", ruleSSSDLDAPClear, finding.ResultPass, ""},
		"servers discovered":       {domain("id_provider = ldap"), "2.9.9", ruleSSSDLDAPClear, finding.ResultUnknown, "discovers its servers"},
		"SASL mechanism":           {domain("id_provider = ldap", "ldap_uri = ldap://a", "ldap_sasl_mech = GSSAPI"), "2.9.9", ruleSSSDLDAPClear, finding.ResultUnknown, "SASL security layer"},
		"start_tls not a boolean":  {domain("id_provider = ldap", "ldap_uri = ldap://a", "ldap_id_use_start_tls = yes"), "2.9.9", ruleSSSDLDAPClear, finding.ResultUnknown, "neither true nor false"},
		"identities not from ldap": {domain("id_provider = files", "auth_provider = krb5"), "2.9.9", ruleSSSDLDAPClear, finding.ResultNotApplicable, "no active domain takes its identities from the ldap provider"},
		"ad provider":              {domain("id_provider = ad", "auth_provider = krb5", "ldap_tls_reqcert = never"), "2.9.9", ruleSSSDCertificate, finding.ResultNotApplicable, "no active domain uses the ldap provider"},

		"reqcert never": {domain("id_provider = ldap", "ldap_tls_reqcert = never"), "2.9.9", ruleSSSDCertificate, finding.ResultFail,
			"[domain/corp] ldap_tls_reqcert value=never line=/etc/sssd/sssd.conf:7"},
		"reqcert allow, ldap for authentication only": {domain("id_provider = files", "auth_provider = ldap", "ldap_tls_reqcert = Allow"), "2.9.9", ruleSSSDCertificate, finding.ResultFail,
			"[domain/corp] ldap_tls_reqcert value=Allow line=/etc/sssd/sssd.conf:8"},
		"reqcert unset":   {domain("id_provider = ldap"), "2.9.9", ruleSSSDCertificate, finding.ResultPass, ""},
		"reqcert demand":  {domain("id_provider = ldap", "ldap_tls_reqcert = demand"), "2.9.9", ruleSSSDCertificate, finding.ResultPass, ""},
		"reqcert unknown": {domain("id_provider = ldap", "ldap_tls_reqcert = maybe"), "2.9.9", ruleSSSDCertificate, finding.ResultUnknown, "not a value sssd-ldap(5) gives"},

		"credentials cached": {domain("id_provider = ldap", "cache_credentials = true"), "2.9.9", ruleSSSDCached, finding.ResultFail,
			"[domain/corp] cache_credentials value=true line=/etc/sssd/sssd.conf:7|[pam] offline_credentials_expiration value=3 line=/etc/sssd/sssd.conf:4"},
		"credentials not cached":   {domain("id_provider = ldap"), "2.9.9", ruleSSSDCached, finding.ResultPass, ""},
		"cache_credentials refuse": {domain("id_provider = ldap", "cache_credentials = on"), "2.9.9", ruleSSSDCached, finding.ResultUnknown, "neither true nor false"},

		"ticket not validated": {domain("id_provider = ldap", "auth_provider = krb5"), "2.9.9", ruleSSSDTicket, finding.ResultFail,
			"[domain/corp] krb5_validate state=not set"},
		"ticket validated":       {domain("id_provider = ldap", "auth_provider = krb5", "krb5_validate = true"), "2.9.9", ruleSSSDTicket, finding.ResultPass, ""},
		"no krb5 authentication": {domain("id_provider = ldap"), "2.9.9", ruleSSSDTicket, finding.ResultNotApplicable, "no active domain authenticates with the krb5 provider"},
		"ipa identities":         {domain("id_provider = ipa", "auth_provider = krb5"), "2.9.9", ruleSSSDTicket, finding.ResultNotApplicable, "krb5 provider"},
	}
	for name, c := range cases {
		got := runSSSD(c.fsys, c.release)[c.key]
		var subjects []string
		for _, e := range got.Evidence {
			subjects = append(subjects, strings.TrimSpace(e.Subject+" "+factText(e)))
		}
		text := got.Reason
		if got.Result == finding.ResultFail {
			text = strings.Join(subjects, "|")
		}
		if got.Result != c.want || !strings.Contains(text, c.text) || c.want == finding.ResultFail && text != c.text {
			t.Errorf("%s: %s %q, want %s %q", name, got.Result, text, c.want, c.text)
		}
	}
}

// The domains SSSD serves are recorded on the presence condition, and a
// snippet whose order the locale decides leaves its rule unknown.
func TestRecordSSSDDomainsAndOrder(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/sssd/sssd.conf":     sssdFile("[sssd]\ndomains = corp\n[domain/corp]\nid_provider = ldap\n"),
		"etc/sssd/conf.d/B.conf": sssdFile("[domain/corp]\ncache_credentials = false\n"),
		"etc/sssd/conf.d/a.conf": sssdFile("[domain/corp]\ncache_credentials = true\n"),
	}
	got := runSSSD(fsys, "2.9.9")
	if c := got[ruleSSSDCached]; c.Result != finding.ResultUnknown || !strings.Contains(c.Reason, "order depends on the locale") {
		t.Errorf("snippets in an order the locale decides: %+v", c)
	}
	present := got["users.sssd_configured"]
	if present.Result != finding.ResultInformational || len(present.Evidence) != 1 ||
		present.Evidence[0].Subject != "[domain/corp]" || factText(present.Evidence[0]) != "state=active" {
		t.Errorf("active domain on the presence condition: %+v", present)
	}
}

// The release sssd --version prints decides which manual applies.
func TestParseSSSDVersion(t *testing.T) {
	for text, want := range map[string]bool{"2.6.3\n": false, "2.9.9": false, "2.10.0": true, "2.10.2": true, "3.0": true} {
		v, err := parseSSSDVersion(text)
		if err != nil || v.runsAsServiceUser() != want || v.text != strings.TrimSpace(text) {
			t.Errorf("%q: %+v %v, want runsAsServiceUser %v", text, v, err, want)
		}
	}
	for _, text := range []string{"", "sssd", "2", "two.ten"} {
		if _, err := parseSSSDVersion(text); err == nil {
			t.Errorf("%q was read as a release", text)
		}
	}
}

// A host configured by a snippet alone has the snippet as its presence.
func TestSSSDSnippetIsPresence(t *testing.T) {
	linux := registry.OSContext{Platform: registry.PlatformLinux, Families: []registry.Distro{registry.DistroGeneric}}
	fsys := fstest.MapFS{"etc/sssd/conf.d/corp.conf": sssdFile("[sssd]\ndomains = corp\n")}
	r := &report{osCtx: linux, index: make(map[registry.FindingKey]int)}
	recordDirectoryClients(r, fsys, directoryClients(linux.Families), nssWiring{}, readPAMStack(fsys, pamLayoutFor(nil), nil))
	for _, c := range r.finish().Conditions {
		if c.Key != "users.sssd_configured" {
			continue
		}
		if c.Finding == nil || len(c.Evidence) != 1 || c.Evidence[0].Subject != "/etc/sssd/conf.d/corp.conf" {
			t.Errorf("snippet with no sssd.conf: %+v", c)
		}
	}
}
