// internal/security/checker/finding_test.go

package checker

import (
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
)

// A checker records only what the definition declares: evidence within the
// declaration is recorded, and a fact outside it panics, as a key with no
// definition does, rather than reaching the rules that read it.
func TestObservedHoldsEvidenceToRecords(t *testing.T) {
	newLinuxReport := func() *report {
		return &report{
			osCtx: registry.OSContext{Platform: registry.PlatformLinux, Families: []registry.Distro{registry.DistroGeneric}},
			index: make(map[registry.FindingKey]int),
		}
	}
	declared := evidence(finding.KindFile, "/usr/bin/x",
		fact(finding.FactMode, "-rwsr-xr-x"), fact(finding.FactReach, finding.ReachRootOnly))

	r := newLinuxReport()
	r.observed("permissions.suid_sgid_binary", declared)
	if got := r.result.Conditions; len(got) != 1 || len(got[0].Evidence) != 1 {
		t.Fatalf("declared evidence was not recorded: %+v", got)
	}

	for name, subject := range map[string]finding.Evidence{
		"an undeclared fact": evidence(finding.KindFile, "/usr/bin/x", fact(finding.FactShell, "/bin/sh")),
		"an undeclared kind": evidence(finding.KindAccount, "alice"),
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("observed accepted evidence its definition does not declare")
				}
			}()
			r := newLinuxReport()
			r.observed("permissions.suid_sgid_binary", declared)
			r.observed("permissions.suid_sgid_binary", subject)
		})
	}
}

// A finding is scored on all the evidence recorded for it, including subjects
// observed after the first: a file any user can reach, recorded second, keeps
// the baseline that the first file alone would have modified, and the severity
// used for filtering follows the host score only when there is one.
func TestFinishScoresTheCompleteEvidence(t *testing.T) {
	ctx := registry.OSContext{Platform: registry.PlatformLinux, Families: []registry.Distro{registry.DistroGeneric}}
	const key = "permissions.suid_sgid_binary"
	def, ok := registry.Lookup(ctx, key)
	if !ok {
		t.Fatal("no definition for " + key)
	}
	rootOnly := func(path string) finding.Evidence {
		return evidence(finding.KindFile, path, fact(finding.FactMode, "-rwsr-xr-x"), fact(finding.FactReach, finding.ReachRootOnly))
	}

	scored := func(subjects ...finding.Evidence) *finding.Finding {
		r := &report{osCtx: ctx, index: make(map[registry.FindingKey]int)}
		for _, subject := range subjects {
			r.observed(key, subject)
		}
		result := r.finish()
		if len(result.Conditions) != 1 || result.Conditions[0].Finding == nil || result.Conditions[0].Finding.Host == nil {
			t.Fatalf("no host score: %+v", result.Conditions)
		}
		return result.Conditions[0].Finding
	}

	all := scored(rootOnly("/usr/bin/a"), rootOnly("/usr/bin/b"))
	if all.Host.CVSS == nil || all.Host.Modified[0].Carried != 2 || finding.EffectiveSeverity(*all) != all.Host.CVSS.Severity {
		t.Errorf("every file root-only: %+v", all.Host)
	}

	mixed := scored(rootOnly("/usr/bin/a"), evidence(finding.KindFile, "/usr/bin/b", fact(finding.FactMode, "-rwsr-xr-x")))
	if mixed.Host.CVSS != nil || len(mixed.Host.Unmodified) != 1 || finding.EffectiveSeverity(*mixed) != def.Severity {
		t.Errorf("a later file reachable by others: %+v", mixed.Host)
	}
}

// The evidence helper keeps facts in the order given and leaves out one with
// no value.
func TestEvidenceOmitsEmptyFacts(t *testing.T) {
	got := evidence(finding.KindFile, "/x", fact(finding.FactMode, "-rw-r--r--"), fact(finding.FactReach, ""), fact(finding.FactUID, "0"))
	if len(got.Facts) != 2 || got.Facts[0].Name != string(finding.FactMode) || got.Facts[1].Name != string(finding.FactUID) {
		t.Errorf("facts = %v", got.Facts)
	}
}
