// internal/security/registry/environment_test.go

package registry

import (
	"maps"
	"slices"
	"strings"
	"testing"

	v4 "github.com/papa0four/orkowatch/internal/cvss/v4"
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
	declared := finding.Evidence{Kind: finding.KindFile, Subject: "/x", Facts: []finding.Fact{{Name: "reach", Value: "root-only"}}}
	if err := d.CheckEvidence(declared); err != nil {
		t.Errorf("declared evidence refused: %v", err)
	}
	if err := d.CheckEvidence(finding.Evidence{Kind: finding.KindAccount, Subject: "a"}); err == nil {
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
				subject := finding.Evidence{Kind: rule.Kind, Subject: "s", Facts: []finding.Fact{{Name: rule.Fact, Value: c.Value}}}
				got := d.Modified(subject)
				want := guide.Passages[c.Guide]
				if len(got) != 1 || got[0].Metric != rule.Metric || got[0].Value != c.Set || got[0].Quote != want.Text || got[0].Section != want.Section || got[0].Because != c.Because {
					t.Errorf("%s: %s=%s derived %+v", label, rule.Fact, c.Value, got)
				}
			}
			unmatched := finding.Evidence{Kind: rule.Kind, Subject: "s", Facts: []finding.Fact{{Name: rule.Fact, Value: "no case has this value"}}}
			if got := d.Modified(unmatched); len(got) != 0 {
				t.Errorf("%s: a value no case names derived %+v", label, got)
			}
			if got := d.Modified(finding.Evidence{Kind: rule.Kind, Subject: "s"}); len(got) != 0 {
				t.Errorf("%s: a subject without %s derived %+v", label, rule.Fact, got)
			}
		}
	}
	if rules == 0 {
		t.Fatal("no shipped definition has a rule, so nothing was exercised")
	}
}

// fileSubject is file evidence recording reach.
func fileSubject(path, reach string) finding.Evidence {
	return finding.Evidence{Kind: finding.KindFile, Subject: path, Facts: []finding.Fact{{Name: finding.FactReach, Value: reach}}}
}

// The same condition scores differently on hosts whose evidence differs: every
// file root-only sets MPR:H, and a file any user can reach, one whose reach was
// not determined, or no file at all leaves the baseline with the reason.
func TestEnvironmentalFollowsTheEvidence(t *testing.T) {
	d := ruleDefinition()
	baseline, err := v4.Parse(d.CVSSVector)
	if err != nil {
		t.Fatal(err)
	}
	modified, err := baseline.With("MPR", "H")
	if err != nil {
		t.Fatal(err)
	}

	all := d.Environmental([]finding.Evidence{fileSubject("/a", finding.ReachRootOnly), fileSubject("/b", finding.ReachRootOnly)})
	switch {
	case all == nil || all.CVSS == nil || len(all.Modified) != 1 || len(all.Unmodified) != 0:
		t.Fatalf("every file root-only: %+v", all)
	case all.CVSS.Vector != modified.String() || all.CVSS.Score != modified.Score() || all.CVSS.Severity != v4.Severity(modified.Score()):
		t.Errorf("score %+v, want %s at %.1f", all.CVSS, modified, modified.Score())
	case all.CVSS.Nomenclature != "CVSS-BE" || all.CVSS.Source != "host evidence" || all.CVSS.CalculatorURL != v4.CalculatorURL(modified.String()):
		t.Errorf("score labeled %+v", all.CVSS)
	case all.Modified[0].Metric != "MPR" || all.Modified[0].Value != "H" || all.Modified[0].Carried != 2 || all.Modified[0].Subjects != 2 || all.Modified[0].Fact.Value != finding.ReachRootOnly:
		t.Errorf("modified %+v", all.Modified[0])
	}

	for name, c := range map[string]struct {
		evidence []finding.Evidence
		reason   []string
	}{
		"one file reachable by others": {
			[]finding.Evidence{fileSubject("/a", finding.ReachRootOnly), {Kind: finding.KindFile, Subject: "/b"}},
			[]string{"of the 2 file subjects, MPR:H on 1 and PR:L on 1; PR:L scores higher, so it stands"},
		},
		"reach not determined": {
			[]finding.Evidence{fileSubject("/a", finding.ReachUndetermined), fileSubject("/b", finding.ReachUndetermined), {Kind: finding.KindFile, Subject: "/c"}},
			[]string{"reach on the 3 file subjects is undetermined on 2 and not recorded on 1, which no case of the rule modifies, so PR:L stands"},
		},
		"one file, reach not determined": {
			[]finding.Evidence{fileSubject("/a", finding.ReachUndetermined)},
			[]string{"reach on the 1 file subject is undetermined on 1, which no case of the rule modifies, so PR:L stands"},
		},
		"no file": {nil, []string{"no file evidence was recorded, so PR:L stands"}},
	} {
		got := d.Environmental(c.evidence)
		if got == nil || got.CVSS != nil || len(got.Modified) != 0 || len(got.Unmodified) != 1 || got.Unmodified[0].Metric != "MPR" {
			t.Errorf("%s: %+v", name, got)
			continue
		}
		for _, want := range c.reason {
			if got.Unmodified[0].Reason != want {
				t.Errorf("%s: reason %q, want %q", name, got.Unmodified[0].Reason, want)
			}
		}
	}

	d.Environment = nil
	if got := d.Environmental([]finding.Evidence{fileSubject("/a", finding.ReachRootOnly)}); got != nil {
		t.Errorf("a definition with no rules scored %+v", got)
	}
}

// For every shipped rule and case, subjects that all carry the case's value set
// the metric, and subjects that disagree score no lower than either value alone
// would: the score never falls below what one subject supports. At least one
// shipped rule moves a finding to another severity, so the host score is not a
// relabeled baseline.
func TestShippedRulesScoreTheHost(t *testing.T) {
	var cases, moved int
	for label, d := range allDefinitions() {
		baseline, err := v4.Parse(d.CVSSVector)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		for _, rule := range d.Environment {
			for _, c := range rule.Cases {
				cases++
				if scoreShippedCase(t, label, d, baseline, rule, c) {
					moved++
				}
			}
		}
	}
	if cases == 0 {
		t.Fatal("no shipped rule was exercised")
	}
	if moved == 0 {
		t.Error("no shipped rule changes a finding's severity")
	}
}

// scoreShippedCase checks one case of a shipped rule on subjects that agree and
// on subjects that disagree, and reports whether agreeing subjects moved the
// finding to another severity.
func scoreShippedCase(t *testing.T, label string, d FindingDefinition, baseline v4.Vector, rule EnvironmentRule, c RuleCase) bool {
	t.Helper()
	subject := func(value string) finding.Evidence {
		return finding.Evidence{Kind: rule.Kind, Subject: "s", Facts: []finding.Fact{{Name: rule.Fact, Value: value}}}
	}
	want, err := baseline.With(rule.Metric, c.Set)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}

	all := d.Environmental([]finding.Evidence{subject(c.Value), subject(c.Value)})
	if all == nil || all.CVSS == nil || all.CVSS.Vector != want.String() {
		t.Errorf("%s: %s=%s on every subject scored %+v, want %s", label, rule.Fact, c.Value, all, want)
		return false
	}

	mixed := d.Environmental([]finding.Evidence{subject(c.Value), subject("no case has this value")})
	score := baseline.Score()
	if mixed.CVSS != nil {
		score = mixed.CVSS.Score
	}
	if score < baseline.Score() || score < want.Score() {
		t.Errorf("%s: disagreeing subjects scored %.1f, below %.1f or %.1f", label, score, baseline.Score(), want.Score())
	}
	return all.CVSS.Severity != d.Severity
}

// Where the values subjects support score the same, the baseline's is kept,
// and a value every subject supports is taken whatever it scores.
func TestHighestKeepsTheBaselineOnATie(t *testing.T) {
	noImpact, err := v4.Parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")
	if err != nil {
		t.Fatal(err)
	}
	rule := EnvironmentRule{Metric: "MPR"}
	if choice, v := highest(noImpact, []ruleYield{{rule: rule, values: []string{"H", notDefined}}}); choice[0] != notDefined || v.String() != noImpact.String() {
		t.Errorf("a tie chose %v, %s", choice, v)
	}
	if choice, v := highest(noImpact, []ruleYield{{rule: rule, values: []string{"H"}}}); choice[0] != "H" || v.Value("MPR") != "H" {
		t.Errorf("a value every subject supports was not taken: %v, %s", choice, v)
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
