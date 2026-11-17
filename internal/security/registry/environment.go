// internal/security/registry/environment.go

package registry

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	v4 "github.com/papa0four/orkowatch/internal/cvss/v4"
	"github.com/papa0four/orkowatch/internal/security/finding"
)

type (
	// Records declares, for each kind of evidence subject a condition's
	// evidence holds, the facts recorded on it. A rule may read only a fact
	// declared here, and a checker may record only what is declared, so the
	// two cannot disagree on what the evidence carries. An empty declaration
	// says the condition carries no evidence.
	Records map[finding.EvidenceKind][]finding.FactName

	// EnvironmentRule turns one recorded fact into a Modified Base metric
	// value. Kind and Fact name the fact; each case sets Metric when the
	// fact has that case's value. A subject with no matching case leaves the
	// metric Not Defined, so the baseline's value stands.
	EnvironmentRule struct {
		Metric string               `yaml:"metric"`
		Kind   finding.EvidenceKind `yaml:"kind"`
		Fact   finding.FactName     `yaml:"fact"`
		Cases  []RuleCase           `yaml:"cases"`
	}

	// RuleCase is one value of a rule's fact and the metric value it sets,
	// with the passage of FIRST's guide that supports it and why the fact
	// meets that passage.
	RuleCase struct {
		Value   string `yaml:"value"`
		Set     string `yaml:"set"`
		Guide   string `yaml:"guide"`
		Because string `yaml:"because"`
	}

	// guidePassage is one quoted passage of FIRST's Implementation Guide and
	// the Modified Base metric value it supports.
	guidePassage struct {
		Section string `yaml:"section"`
		Text    string `yaml:"text"`
		Metric  string `yaml:"metric"`
		Value   string `yaml:"value"`
	}

	// guideFile is the bundled set of passages, with the guide they were
	// quoted from and the date they were read.
	guideFile struct {
		Source   string                  `yaml:"source"`
		Title    string                  `yaml:"title"`
		Verified string                  `yaml:"verified"`
		Passages map[string]guidePassage `yaml:"passages"`
	}
)

var (
	//go:embed data/cvss_guide.yaml
	guideData []byte

	// guide is the bundled set of passages. Definitions are validated against
	// it as they load, so it is read first.
	guide = mustLoadGuide(guideData)
)

// mustLoadGuide decodes the bundled passages strictly and panics on one a rule
// could not rest on: no text, or a metric value the specification does not give.
func mustLoadGuide(data []byte) guideFile {
	var file guideFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil {
		panic("registry: failed to parse embedded YAML cvss_guide.yaml: " + err.Error())
	}
	if file.Source == "" || file.Title == "" || file.Verified == "" {
		panic("registry: cvss_guide.yaml names no source, title or verification date")
	}
	for id, p := range file.Passages {
		if p.Section == "" || strings.TrimSpace(p.Text) == "" {
			panic(fmt.Sprintf("registry: cvss_guide.yaml: %s has no section or text", id))
		}
		if err := checkModifiedValue(p.Metric, p.Value); err != nil {
			panic(fmt.Sprintf("registry: cvss_guide.yaml: %s: %v", id, err))
		}
	}
	return file
}

// checkModifiedValue reports whether value is one the specification gives the
// Modified Base metric, other than Not Defined, which modifies nothing.
func checkModifiedValue(metric, value string) error {
	_, values, ok := v4.ModifiedBase(metric)
	switch {
	case !ok:
		return fmt.Errorf("%q is not a Modified Base metric", metric)
	case value == "X" || !slices.Contains(values, value):
		return fmt.Errorf("%s value %q is not one of %s other than X", metric, value, strings.Join(values, ", "))
	}
	return nil
}

// validateRecords confirms d declares what its evidence carries, using only
// kinds and fact names the checkers have.
func (d FindingDefinition) validateRecords() error {
	if d.Records == nil {
		return errors.New("records is missing: declare the facts its evidence carries, or {} for none")
	}
	for kind, facts := range d.Records {
		if !kind.Known() {
			return fmt.Errorf("records: %q is not an evidence kind", kind)
		}
		for i, name := range facts {
			if !name.Known() {
				return fmt.Errorf("records: %s: %q is not a fact name", kind, name)
			}
			if slices.Contains(facts[:i], name) {
				return fmt.Errorf("records: %s: %s is declared twice", kind, name)
			}
		}
	}
	return nil
}

// validateEnvironment confirms every rule of d reads a fact d records, sets a
// value the specification gives the metric and the baseline does not already
// have, and rests each case on a bundled passage of the guide for that value.
// A metric has at most one rule, so a subject cannot set it two ways.
func (d FindingDefinition) validateEnvironment() error {
	if len(d.Environment) == 0 {
		return nil
	}
	baseline, err := v4.Parse(d.CVSSVector)
	if err != nil {
		return fmt.Errorf("environment: %w", err)
	}
	for i, rule := range d.Environment {
		if slices.ContainsFunc(d.Environment[:i], func(r EnvironmentRule) bool { return r.Metric == rule.Metric }) {
			return fmt.Errorf("environment: %s has more than one rule", rule.Metric)
		}
		if err := d.validateRule(rule, baseline); err != nil {
			return fmt.Errorf("environment: %s: %w", rule.Metric, err)
		}
	}
	return nil
}

// validateRule confirms one rule against the definition's records and baseline.
func (d FindingDefinition) validateRule(rule EnvironmentRule, baseline v4.Vector) error {
	base, _, ok := v4.ModifiedBase(rule.Metric)
	if !ok {
		return errors.New("is not a Modified Base metric")
	}
	if !slices.Contains(d.Records[rule.Kind], rule.Fact) {
		return fmt.Errorf("reads %s on %s, which records does not declare", rule.Fact, rule.Kind)
	}
	if len(rule.Cases) == 0 {
		return errors.New("has no cases")
	}
	for i, c := range rule.Cases {
		switch {
		case slices.ContainsFunc(rule.Cases[:i], func(prior RuleCase) bool { return prior.Value == c.Value }):
			return fmt.Errorf("case %q is given twice", c.Value)
		case !rule.Fact.Takes(c.Value):
			return fmt.Errorf("case %q is not a value %s can record", c.Value, rule.Fact)
		case strings.TrimSpace(c.Because) == "":
			return fmt.Errorf("case %q states no reason", c.Value)
		case c.Set == baseline.Value(base):
			return fmt.Errorf("case %q sets %s, the value the baseline already gives %s", c.Value, c.Set, base)
		}
		if err := checkModifiedValue(rule.Metric, c.Set); err != nil {
			return fmt.Errorf("case %q: %w", c.Value, err)
		}
		passage, ok := guide.Passages[c.Guide]
		switch {
		case !ok:
			return fmt.Errorf("case %q cites %q, which is not a bundled passage of the guide", c.Value, c.Guide)
		case passage.Metric != rule.Metric || passage.Value != c.Set:
			return fmt.Errorf("case %q cites %s, which supports %s:%s, not %s:%s",
				c.Value, c.Guide, passage.Metric, passage.Value, rule.Metric, c.Set)
		}
	}
	return nil
}

// CheckEvidence reports whether e carries only what d declares in Records. The
// checker calls it on every subject it records, so a fact a rule reads cannot
// be renamed or dropped at one end without the other noticing.
func (d FindingDefinition) CheckEvidence(e finding.Evidence) error {
	facts, ok := d.Records[finding.EvidenceKind(e.Kind)]
	if !ok {
		return fmt.Errorf("evidence of kind %q, which records does not declare", e.Kind)
	}
	for _, f := range e.Facts {
		if !slices.Contains(facts, finding.FactName(f.Name)) {
			return fmt.Errorf("fact %q on %s evidence, which records does not declare", f.Name, e.Kind)
		}
	}
	return nil
}

// Modified returns the Modified Base metrics d's rules derive from one evidence
// subject, each with the fact and the passage behind it. It is empty when no
// rule reads this kind of subject or no case matches its fact.
func (d FindingDefinition) Modified(e finding.Evidence) []finding.ModifiedMetric {
	var out []finding.ModifiedMetric
	for _, rule := range d.Environment {
		if string(rule.Kind) != e.Kind {
			continue
		}
		for _, f := range e.Facts {
			if f.Name != string(rule.Fact) {
				continue
			}
			for _, c := range rule.Cases {
				if c.Value != f.Value {
					continue
				}
				passage := guide.Passages[c.Guide]
				out = append(out, finding.ModifiedMetric{
					Metric:  rule.Metric,
					Value:   c.Set,
					Fact:    f,
					Because: c.Because,
					Section: passage.Section,
					Quote:   passage.Text,
				})
			}
		}
	}
	return out
}
