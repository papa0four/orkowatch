//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/security/checker/users_unix_test.go

package checker

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
)

// A directory client's configuration file is a fact either way: present, it
// is recorded with the file as evidence; absent, with the reason; neither is a
// finding, and the check's result is what its other conditions conclude. A file
// whose presence cannot be determined is an error, not absence.
func TestClientConfigIsInformational(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "krb5.conf")
	if err := os.WriteFile(present, []byte("[libdefaults]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configs := []clientConfig{
		{filepath.Join(dir, "ldap.conf"), "LDAP", "users.ldap_configured"},
		{present, "Kerberos", "users.kerberos_configured"},
		{filepath.Join(present, "sssd.conf"), "SSSD", "users.sssd_configured"},
	}
	linux := registry.OSContext{Platform: registry.PlatformLinux, Families: []registry.Distro{registry.DistroGeneric}}

	r := &report{osCtx: linux, index: make(map[registry.FindingKey]int)}
	recordClientConfigs(r, configs[:2])
	r.pass("users.empty_password_hash")
	result := r.finish()

	got := make(map[string]finding.Condition, len(result.Conditions))
	for _, c := range result.Conditions {
		got[c.Key] = c
	}
	if c := got["users.ldap_configured"]; c.Result != finding.ResultInformational || c.Reason != configs[0].path+" is not present" || len(c.Evidence) != 0 {
		t.Errorf("an absent file: %+v", c)
	}
	c := got["users.kerberos_configured"]
	if c.Result != finding.ResultInformational || c.Finding == nil || len(c.Evidence) != 1 || c.Evidence[0].Subject != present {
		t.Errorf("a present file: %+v", c)
	}
	if c.Finding != nil && (c.Finding.Severity != finding.SeverityNone || c.Finding.CVSS == nil || c.Finding.CVSS.Score != 0 || len(c.Finding.Techniques) != 0) {
		t.Errorf("a present file is scored %+v with techniques %v", c.Finding.CVSS, c.Finding.Techniques)
	}
	if result.Result != finding.ResultPass {
		t.Errorf("the check concluded %s, not the pass its other condition holds", result.Result)
	}

	r = &report{osCtx: linux, index: make(map[registry.FindingKey]int)}
	recordClientConfigs(r, configs[2:])
	if c := r.finish().Conditions[0]; c.Result != finding.ResultError {
		t.Errorf("a file whose presence could not be determined: %+v", c)
	}
}
