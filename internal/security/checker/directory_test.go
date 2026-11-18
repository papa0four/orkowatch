// internal/security/checker/directory_test.go

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

// A database line names its services without the actions between them, and
// only the account databases are read.
func TestReadNSSwitch(t *testing.T) {
	data := "# passwd: ldap\n" +
		"passwd:     sss files systemd # trailing\n" +
		"group: files [ SUCCESS = merge ] sss\n" +
		"hosts: files dns\n" +
		"passwd_compat: ldap\n"
	got := readNSSwitch([]byte(data), nssDatabases)
	want := []nssLine{
		{database: "passwd", line: 2, value: "sss files systemd", services: []string{"sss", "files", "systemd"}},
		{database: "group", line: 3, value: "files [ SUCCESS = merge ] sss", services: []string{"files", "sss"}},
		{database: "passwd_compat", line: 5, value: "ldap", services: []string{"ldap"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

// The OpenLDAP client is looked for where each family's libldap reads it, and
// a distribution of no recognised family is not guessed at.
func TestOpenLDAPConfig(t *testing.T) {
	cases := map[registry.Distro]string{
		registry.DistroDebian:  "/etc/ldap/ldap.conf",
		registry.DistroRHEL:    "/etc/openldap/ldap.conf",
		registry.DistroFedora:  "/etc/openldap/ldap.conf",
		registry.DistroArch:    "/etc/openldap/ldap.conf",
		registry.DistroSUSE:    "/etc/openldap/ldap.conf",
		registry.DistroAlpine:  "/etc/openldap/ldap.conf",
		registry.DistroGeneric: "",
	}
	for family, want := range cases {
		if got := openLDAPConfig([]registry.Distro{family, registry.DistroGeneric}); got != want {
			t.Errorf("%s: %q, want %q", family, got, want)
		}
	}
}

// The name service switch is read from /usr/etc where /etc has none, and not
// at all on Alpine, whose C library has no name service switch.
func TestReadNSSWiring(t *testing.T) {
	fsys := fstest.MapFS{"usr/etc/nsswitch.conf": {Data: []byte("passwd: compat sss\n")}}
	nss, problems := readNSSWiring(fsys, []registry.Distro{registry.DistroSUSE})
	if nss.path != "/usr/etc/nsswitch.conf" || len(nss.lines) != 1 || len(problems) != 0 {
		t.Errorf("vendor nsswitch.conf: %+v %v", nss, problems)
	}
	fsys["etc/nsswitch.conf"] = &fstest.MapFile{Data: []byte("passwd: files\n")}
	if nss, _ = readNSSWiring(fsys, []registry.Distro{registry.DistroSUSE}); nss.path != "/etc/nsswitch.conf" {
		t.Errorf("/etc/nsswitch.conf did not take precedence: %+v", nss)
	}
	if nss, _ = readNSSWiring(fsys, []registry.Distro{registry.DistroAlpine}); nss.path != "" || nss.lines != nil {
		t.Errorf("Alpine: %+v", nss)
	}
}

// statFailure fails every Stat with a permission error, as a directory the
// auditing user cannot search does.
type statFailure struct{ fstest.MapFS }

func (statFailure) Stat(string) (fs.FileInfo, error) { return nil, fs.ErrPermission }

// Each client records its file and its wiring when either is present, and the
// reason when neither is. Being recorded is a fact, never a finding.
func TestRecordDirectoryClients(t *testing.T) {
	linux := registry.OSContext{Platform: registry.PlatformLinux, Families: []registry.Distro{registry.DistroDebian, registry.DistroGeneric}}
	fsys := fstest.MapFS{
		"etc/krb5.conf":         {Data: []byte("[libdefaults]\n")},
		"etc/nsswitch.conf":     {Data: []byte("passwd: files sss\ngroup: files sss\n")},
		"etc/pam.d/common-auth": {Data: []byte("auth [success=1 default=ignore] pam_sss.so use_first_pass\n")},
		"etc/pam.d/login":       {Data: []byte("@include common-auth\n")},
	}
	clients := directoryClients(linux.Families)
	nss, _ := readNSSWiring(fsys, linux.Families)
	stack := readPAMStack(fsys, pamLayoutFor(linux.Families), clientModules(clients))

	r := &report{osCtx: linux, index: make(map[registry.FindingKey]int)}
	recordDirectoryClients(r, fsys, clients, nss, stack)
	r.pass("users.empty_password_hash")
	result := r.finish()
	got := map[string]finding.Condition{}
	for _, c := range result.Conditions {
		got[c.Key] = c
	}

	if c := got["users.ldap_configured"]; c.Result != finding.ResultInformational || c.Reason != "/etc/ldap/ldap.conf is not present" || len(c.Evidence) != 0 {
		t.Errorf("OpenLDAP client absent: %+v", c)
	}
	if c := got["users.nslcd_configured"]; c.Result != finding.ResultInformational ||
		c.Reason != "/etc/nslcd.conf is not present, the name service switch does not name ldap, and no PAM rule names pam_ldap.so" {
		t.Errorf("nslcd absent and unwired: %+v", c)
	}
	if c := got["users.kerberos_configured"]; c.Finding == nil || len(c.Evidence) != 1 || c.Evidence[0].Subject != "/etc/krb5.conf" {
		t.Errorf("Kerberos file present and unwired: %+v", c)
	}
	sssd := got["users.sssd_configured"]
	var subjects []string
	for _, e := range sssd.Evidence {
		subjects = append(subjects, e.Kind+" "+e.Subject+" "+factText(e))
	}
	wantSubjects := []string{
		"nss-database passwd line=/etc/nsswitch.conf:1 value=files sss",
		"nss-database group line=/etc/nsswitch.conf:2 value=files sss",
		"pam-rule auth pam_sss.so line=/etc/pam.d/common-auth:1 services=common-auth, login",
	}
	if sssd.Result != finding.ResultInformational || sssd.Finding == nil || !reflect.DeepEqual(subjects, wantSubjects) {
		t.Errorf("SSSD wired with no file: %s %v", sssd.Result, subjects)
	}
	for key, c := range got {
		if c.Finding != nil && (c.Finding.Severity != finding.SeverityNone || c.Finding.CVSS == nil || c.Finding.CVSS.Score != 0) {
			t.Errorf("%s is scored %+v", key, c.Finding.CVSS)
		}
	}
	if result.Result != finding.ResultPass {
		t.Errorf("the check concluded %s, not the pass its other condition holds", result.Result)
	}
}

// A client whose file's presence cannot be determined is an error, and one
// whose path is not established for the distribution is not checked.
func TestRecordDirectoryClientsUndetermined(t *testing.T) {
	unknown := registry.OSContext{Platform: registry.PlatformLinux, Families: []registry.Distro{registry.DistroGeneric}}
	r := &report{osCtx: unknown, index: make(map[registry.FindingKey]int)}
	recordDirectoryClients(r, statFailure{fstest.MapFS{}}, directoryClients(unknown.Families), nssWiring{}, readPAMStack(fstest.MapFS{}, pamLayoutFor(nil), nil))
	for _, c := range r.finish().Conditions {
		switch {
		case c.Key == "users.ldap_configured" && (c.Result != finding.ResultNotChecked || !strings.Contains(c.Reason, "not established")):
			t.Errorf("OpenLDAP client on an unrecognised distribution: %+v", c)
		case c.Key != "users.ldap_configured" && (c.Result != finding.ResultError || !strings.Contains(c.Reason, fs.ErrPermission.Error())):
			t.Errorf("%s whose presence is unknown: %+v", c.Key, c)
		}
	}
}

// factText renders an entry's facts as name=value pairs.
func factText(e finding.Evidence) string {
	parts := make([]string, 0, len(e.Facts))
	for _, f := range e.Facts {
		parts = append(parts, f.Name+"="+f.Value)
	}
	return strings.Join(parts, " ")
}
