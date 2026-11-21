// internal/security/audit/undefined_test.go

package audit

import (
	"context"
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
)

// A check the platform has no definitions for is not run: it reports
// notchecked with the reason, takes no time, and its text ends after the
// header where a check that ran would say it found nothing. The platform's
// definitions are stood in for, so the gate is tested whatever the data files
// define.
func TestCheckWithoutDefinitionsIsNotRun(t *testing.T) {
	undefined := []string{"firewall"}
	sa := NewSecurityAuditor(Options{Checks: undefined, HostInfo: &osfingerprint.OSInfo{}})
	sa.osContext = registry.OSContext{Platform: registry.PlatformUnix, Families: []registry.Distro{registry.DistroFreeBSD}}
	sa.defines = func(_ registry.OSContext, check string) bool { return check != "firewall" }

	result, err := sa.RunAudit(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	view := result.View(finding.SeverityNone)
	for _, check := range view.Results {
		switch {
		case check.Key == "users", check.Key == "ssh", check.Key == permissionsCheck:
			if check.Result != finding.ResultNotSelected {
				t.Errorf("%s: %s, want notselected", check.Key, check.Result)
			}
		case check.Result != finding.ResultNotChecked,
			check.Reason != "no finding definitions for the "+check.Key+" check on FreeBSD",
			check.Duration != "", len(check.Conditions) != 0:
			t.Errorf("%s: %s %q, duration %q, %d conditions; want notchecked and nothing run",
				check.Key, check.Result, check.Reason, check.Duration, len(check.Conditions))
		}
	}

	var out strings.Builder
	if err := WriteViewText(&out, view); err != nil {
		t.Fatal(err)
	}
	if text := out.String(); strings.Contains(text, "No findings at or above") || !strings.Contains(text, "Result: NOTCHECKED") {
		t.Errorf("a check that did not run is reported as one that found nothing:\n%s", text)
	}
}

// The name of each check is what its rule keys begin with: the platforms
// that define every check define each by its name.
func TestCheckNamesAreKeyPrefixes(t *testing.T) {
	complete := []registry.OSContext{
		{Platform: registry.PlatformLinux, Families: []registry.Distro{registry.DistroGeneric}},
		{Platform: registry.PlatformWindows},
	}
	for _, runner := range NewSecurityAuditor(Options{}).checkRunners() {
		for _, ctx := range complete {
			if !registry.Defines(ctx, runner.name) {
				t.Errorf("%s: no definition's key begins with %q", ctx.DisplayLabel(), runner.name+".")
			}
		}
	}
}
