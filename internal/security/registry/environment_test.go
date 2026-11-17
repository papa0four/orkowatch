// internal/security/registry/environment_test.go

package registry

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// ruleDefinition is a definition with a baseline, records and one rule that
// loads, for the refusal cases to break one thing at a time.
func ruleDefinition() FindingDefinition {
	return FindingDefinition{
		Severity:   "HIGH",
		CVSSScore:  8.5,
		CVSSVector: "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		Records:    Records{finding.KindFile: {finding.FactMode, finding.FactReach}},
		Environment: []EnvironmentRule{{
			Metric: "MPR",
			Kind:   finding.KindFile,
			Fact:   finding.FactReach,
			Cases: []RuleCase{{
				Value:   finding.ReachRootOnly,
				Set:     "H",
				Guide:   "mpr-restricting-access-to-administrative-users",
				Because: "only root can reach it",
			}},
		}},
	}
}

// The registry refuses a definition whose records or rules it could not trust,
// each for its own reason.
func TestEnvironmentRefusals(t *testing.T) {
	good := ruleDefinition()
	if err := good.validateRecords(); err != nil {
		t.Fatalf("good records refused: %v", err)
	}
	if err := good.validateEnvironment(); err != nil {
		t.Fatalf("good rule refused: %v", err)
	}

	cases := map[string]struct {
		mutate  func(d *FindingDefinition)
		wantErr string
	}{
		"no records":      {func(d *FindingDefinition) { d.Records = nil }, "records is missing"},
		"an unknown kind": {func(d *FindingDefinition) { d.Records["fiel"] = nil }, `"fiel" is not an evidence kind`},
		"an unknown fact": {func(d *FindingDefinition) { d.Records[finding.KindFile] = []finding.FactName{"reech"} }, `"reech" is not a fact name`},
		"a fact declared twice": {func(d *FindingDefinition) {
			d.Records[finding.KindFile] = []finding.FactName{finding.FactMode, finding.FactMode}
		}, "declared twice"},
		"a Base metric":        {func(d *FindingDefinition) { d.Environment[0].Metric = "PR" }, "not a Modified Base metric"},
		"a fact records lacks": {func(d *FindingDefinition) { d.Environment[0].Fact = finding.FactUID }, "which records does not declare"},
		"a kind records lacks": {func(d *FindingDefinition) { d.Environment[0].Kind = finding.KindAccount }, "which records does not declare"},
		"no cases":             {func(d *FindingDefinition) { d.Environment[0].Cases = nil }, "has no cases"},
		"a case given twice": {func(d *FindingDefinition) {
			d.Environment[0].Cases = append(d.Environment[0].Cases, d.Environment[0].Cases[0])
		}, "given twice"},
		"a value the fact cannot take": {func(d *FindingDefinition) { d.Environment[0].Cases[0].Value = "everyone" }, "not a value reach can record"},
		"no reason":                    {func(d *FindingDefinition) { d.Environment[0].Cases[0].Because = " " }, "states no reason"},
		"the baseline's own value":     {func(d *FindingDefinition) { d.Environment[0].Cases[0].Set = "L" }, "the baseline already gives PR"},
		"a value outside the metric":   {func(d *FindingDefinition) { d.Environment[0].Cases[0].Set = "S" }, `value "S" is not one of`},
		"Not Defined":                  {func(d *FindingDefinition) { d.Environment[0].Cases[0].Set = "X" }, `value "X" is not one of`},
		"no passage":                   {func(d *FindingDefinition) { d.Environment[0].Cases[0].Guide = "" }, "not a bundled passage"},
		"a passage for another value":  {func(d *FindingDefinition) { d.Environment[0].Cases[0].Set = "N" }, "supports MPR:H, not MPR:N"},
		"two rules for one metric":     {func(d *FindingDefinition) { d.Environment = append(d.Environment, d.Environment[0]) }, "more than one rule"},
		"a rule with no usable vector": {func(d *FindingDefinition) { d.CVSSVector = "" }, "environment:"},
	}
	for name, c := range cases {
		d := ruleDefinition()
		c.mutate(&d)
		err := d.validateRecords()
		if err == nil {
			err = d.validateEnvironment()
		}
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: error %v, want one containing %q", name, err, c.wantErr)
		}
	}
}

// Evidence carrying a kind or fact the definition does not declare is refused,
// and evidence within the declaration is not.
func TestCheckEvidence(t *testing.T) {
	d := ruleDefinition()
	declared := finding.Evidence{Kind: string(finding.KindFile), Subject: "/x", Facts: []finding.Fact{{Name: "reach", Value: "root-only"}}}
	if err := d.CheckEvidence(declared); err != nil {
		t.Errorf("declared evidence refused: %v", err)
	}
	if err := d.CheckEvidence(finding.Evidence{Kind: string(finding.KindAccount), Subject: "a"}); err == nil {
		t.Error("evidence of an undeclared kind was accepted")
	}
	undeclared := declared
	undeclared.Facts = []finding.Fact{{Name: "uid", Value: "0"}}
	if err := d.CheckEvidence(undeclared); err == nil {
		t.Error("an undeclared fact was accepted")
	}
}

// Every shipped rule sets its metric for each of its cases, with the passage it
// cites, and sets nothing for a subject whose fact matches no case or that
// lacks the fact.
func TestShippedRulesDeriveEachCase(t *testing.T) {
	var rules int
	for label, d := range allDefinitions() {
		for _, rule := range d.Environment {
			rules++
			for _, c := range rule.Cases {
				subject := finding.Evidence{Kind: string(rule.Kind), Subject: "s", Facts: []finding.Fact{{Name: string(rule.Fact), Value: c.Value}}}
				got := d.Modified(subject)
				want := guide.Passages[c.Guide]
				if len(got) != 1 || got[0].Metric != rule.Metric || got[0].Value != c.Set || got[0].Quote != want.Text || got[0].Section != want.Section || got[0].Because != c.Because {
					t.Errorf("%s: %s=%s derived %+v", label, rule.Fact, c.Value, got)
				}
			}
			unmatched := finding.Evidence{Kind: string(rule.Kind), Subject: "s", Facts: []finding.Fact{{Name: string(rule.Fact), Value: "no case has this value"}}}
			if got := d.Modified(unmatched); len(got) != 0 {
				t.Errorf("%s: a value no case names derived %+v", label, got)
			}
			if got := d.Modified(finding.Evidence{Kind: string(rule.Kind), Subject: "s"}); len(got) != 0 {
				t.Errorf("%s: a subject without %s derived %+v", label, rule.Fact, got)
			}
		}
	}
	if rules == 0 {
		t.Fatal("no shipped definition has a rule, so nothing was exercised")
	}
}

// A key defined in more than one file is observed by the same checker code, so
// every file declares the same records for it. A file loaded only on a platform
// neither test machine runs is held to the declaration a tested file makes.
func TestSharedKeysDeclareTheSameRecords(t *testing.T) {
	type declared struct {
		label   string
		records Records
	}
	byKey := map[string]declared{}
	for _, label := range slices.Sorted(maps.Keys(allDefinitions())) {
		d := allDefinitions()[label]
		key := label[strings.LastIndex(label, "/")+1:]
		first, seen := byKey[key]
		if !seen {
			byKey[key] = declared{label, d.Records}
			continue
		}
		if !sameRecords(first.records, d.Records) {
			t.Errorf("%s declares %v, %s declares %v", label, d.Records, first.label, first.records)
		}
	}
}

// sameRecords reports whether two declarations hold the same facts per kind,
// in any order.
func sameRecords(a, b Records) bool {
	if len(a) != len(b) {
		return false
	}
	for kind, facts := range a {
		other, ok := b[kind]
		if !ok || len(other) != len(facts) {
			return false
		}
		for _, f := range facts {
			if !slices.Contains(other, f) {
				return false
			}
		}
	}
	return true
}
