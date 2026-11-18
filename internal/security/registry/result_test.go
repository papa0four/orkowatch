// internal/security/registry/result_test.go

package registry

import (
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// A definition declares fail, notapplicable or informational, and no result
// that only an evaluation can reach.
func TestDeclaredResults(t *testing.T) {
	linux := OSContext{Platform: PlatformLinux, Families: []Distro{DistroGeneric}}
	base, ok := Lookup(linux, "users.ldap_configured")
	if !ok {
		t.Fatal("no definition for users.ldap_configured")
	}
	for _, result := range []finding.Result{finding.ResultNotApplicable, finding.ResultInformational} {
		d := base
		d.Result = result
		if _, err := d.validated(); err != nil {
			t.Errorf("%s was refused: %v", result, err)
		}
	}
	for _, result := range []finding.Result{finding.ResultPass, finding.ResultError, finding.ResultUnknown, finding.ResultNotChecked, finding.ResultNotSelected} {
		d := base
		d.Result = result
		if _, err := d.validated(); err == nil || !strings.Contains(err.Error(), "not one a definition can declare") {
			t.Errorf("%s was not refused: %v", result, err)
		}
	}
}

// A directory client's configuration file being present is a fact, scored
// 0.0 with severity NONE, and makes no ATT&CK technique available.
func TestClientConfigDefinitionsRecordAFact(t *testing.T) {
	linux := OSContext{Platform: PlatformLinux, Families: []Distro{DistroGeneric}}
	for _, key := range []FindingKey{"users.ldap_configured", "users.kerberos_configured", "users.sssd_configured"} {
		d, ok := Lookup(linux, key)
		if !ok {
			t.Errorf("%s: no definition", key)
			continue
		}
		if d.Result != finding.ResultInformational || d.Severity != finding.SeverityNone || d.CVSSScore != 0 || len(d.AttackTechniques) != 0 {
			t.Errorf("%s: result %s, severity %s, score %.1f, techniques %v", key, d.Result, d.Severity, d.CVSSScore, d.AttackTechniques)
		}
	}
}
