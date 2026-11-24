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
	"github.com/papa0four/orkowatch/internal/render"
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
	case value == notDefined || !slices.Contains(values, value):
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
	facts, ok := d.Records[e.Kind]
	if !ok {
		return fmt.Errorf("evidence of kind %q, which records does not declare", e.Kind)
	}
	for _, f := range e.Facts {
		if !slices.Contains(facts, f.Name) {
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
		if rule.Kind != e.Kind {
			continue
		}
		for _, f := range e.Facts {
			if f.Name != rule.Fact {
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

// notDefined is the value a Modified Base metric takes when it modifies
// nothing, so its Base metric's value stands.
const notDefined = "X"

// ruleYield is what one rule's subjects support: each value of its metric some
// subject supports, in the order first seen, with how many subjects support it
// and what the rule derived for it. A subject no case matches supports Not
// Defined.
type ruleYield struct {
	rule     EnvironmentRule
	subjects int
	values   []string
	carried  map[string]int
	derived  map[string]finding.ModifiedMetric
	recorded []string
	counts   map[string]int
}

// Environmental scores the condition d defines on this host, from every
// evidence subject the checker recorded for it. Each rule is evaluated across
// the subjects of its kind, and each subject supports the value its matching
// case sets, or the baseline's when none matches. The Specification does not
// say how one score follows from subjects that support different values, so
// owatch takes the combination of supported values that scores highest, and
// the baseline's value where two score the same: the score never falls below
// what any one subject supports, which is the reasonable worst case the
// Specification assumes where it has no explicit value. A metric no subject
// supports changing is reported as unmodified with what was recorded. It is nil
// for a definition with no rules, which is scored by its baseline alone.
func (d FindingDefinition) Environmental(evidence []finding.Evidence) *finding.HostScore {
	if len(d.Environment) == 0 {
		return nil
	}
	baseline, err := v4.Parse(d.CVSSVector)
	if err != nil {
		panic("registry: a definition with rules has a baseline that does not parse, which load refuses: " + err.Error())
	}

	yields := make([]ruleYield, len(d.Environment))
	for i, rule := range d.Environment {
		yields[i] = d.yield(rule, evidence)
	}
	choice, vector := highest(baseline, yields)

	host := &finding.HostScore{}
	for i, y := range yields {
		value := choice[i]
		if value == notDefined {
			host.Unmodified = append(host.Unmodified, finding.UnmodifiedMetric{Metric: y.rule.Metric, Reason: y.unmodifiedReason(baseline)})
			continue
		}
		m := y.derived[value]
		m.Carried, m.Subjects = y.carried[value], y.subjects
		host.Modified = append(host.Modified, m)
	}
	if len(host.Modified) > 0 {
		host.CVSS = labeledScore(vector, "host evidence", "Modified Base metrics derived from evidence recorded on this host")
	}
	return host
}

// yield collects what the subjects of rule's kind support.
func (d FindingDefinition) yield(rule EnvironmentRule, evidence []finding.Evidence) ruleYield {
	y := ruleYield{
		rule:    rule,
		carried: make(map[string]int),
		derived: make(map[string]finding.ModifiedMetric),
		counts:  make(map[string]int),
	}
	for _, e := range evidence {
		if e.Kind != rule.Kind {
			continue
		}
		y.subjects++

		value := notDefined
		if m, ok := d.derives(rule, e); ok {
			value = m.Value
			if _, seen := y.derived[value]; !seen {
				y.derived[value] = m
			}
		}
		y.values = tally(y.values, y.carried, value)
		y.recorded = tally(y.recorded, y.counts, recordedValue(e, rule.Fact))
	}
	if y.subjects == 0 {
		y.values = []string{notDefined}
	}
	return y
}

// derives returns the metric rule derives from one subject, if a case matches.
func (d FindingDefinition) derives(rule EnvironmentRule, e finding.Evidence) (finding.ModifiedMetric, bool) {
	for _, m := range d.Modified(e) {
		if m.Metric == rule.Metric {
			return m, true
		}
	}
	return finding.ModifiedMetric{}, false
}

// recordedValue is the value of fact on e, as the reason for an unmodified
// metric reports it.
func recordedValue(e finding.Evidence, fact finding.FactName) string {
	for _, f := range e.Facts {
		if f.Name == fact {
			return f.Value
		}
	}
	return "not recorded"
}

// tally counts value, adding it to order the first time it is seen, so a
// reason lists values in the order the checker recorded them.
func tally(order []string, counts map[string]int, value string) []string {
	if counts[value] == 0 {
		order = append(order, value)
	}
	counts[value]++
	return order
}

// highest returns, for each rule, the value its subjects support that gives the
// highest score in combination with the others, and the vector that scores it.
// Among combinations that score the same, the one modifying fewer metrics wins,
// so a tie keeps the baseline's value.
func highest(baseline v4.Vector, yields []ruleYield) ([]string, v4.Vector) {
	choice := make([]string, len(yields))
	var best []string
	var bestVector v4.Vector
	bestScore, bestModified := -1.0, 0

	var walk func(i int, v v4.Vector, modified int)
	walk = func(i int, v v4.Vector, modified int) {
		if i == len(yields) {
			score := v.Score()
			if best == nil || score > bestScore || (score == bestScore && modified < bestModified) {
				best, bestVector, bestScore, bestModified = slices.Clone(choice), v, score, modified
			}
			return
		}
		for _, value := range yields[i].values {
			choice[i] = value
			next, count := v, modified
			if value != notDefined {
				var err error
				if next, err = v.With(yields[i].rule.Metric, value); err != nil {
					panic("registry: a rule sets a value load validated and the scorer refuses: " + err.Error())
				}
				count++
			}
			walk(i+1, next, count)
		}
	}
	walk(0, baseline, 0)
	return best, bestVector
}

// unmodifiedReason says why the rule left its metric at the baseline's value:
// nothing of its kind was recorded, nothing recorded matches a case, or the
// subjects that do are outscored by those that keep the baseline. Each count
// is written so the sentence agrees with it, one subject or many.
func (y ruleYield) unmodifiedReason(baseline v4.Vector) string {
	base, _, _ := v4.ModifiedBase(y.rule.Metric)
	kept := fmt.Sprintf("%s:%s", base, baseline.Value(base))
	if y.subjects == 0 {
		return fmt.Sprintf("no %s evidence was recorded, so %s stands", y.rule.Kind, kept)
	}
	subjects := render.Count(y.subjects, fmt.Sprintf("%s subject", y.rule.Kind), fmt.Sprintf("%s subjects", y.rule.Kind))
	if len(y.derived) == 0 {
		recorded := make([]string, 0, len(y.recorded))
		for _, value := range y.recorded {
			recorded = append(recorded, fmt.Sprintf("%s on %d", value, y.counts[value]))
		}
		return fmt.Sprintf("%s on the %s is %s, which no case of the rule modifies, so %s stands",
			y.rule.Fact, subjects, listOf(recorded), kept)
	}
	supported := make([]string, 0, len(y.values)+1)
	for _, value := range y.values {
		if value != notDefined {
			supported = append(supported, fmt.Sprintf("%s:%s on %d", y.rule.Metric, value, y.carried[value]))
		}
	}
	supported = append(supported, fmt.Sprintf("%s on %d", kept, y.carried[notDefined]))
	return fmt.Sprintf("of the %s, %s; %s scores higher, so it stands", subjects, listOf(supported), kept)
}

// listOf joins items as a sentence lists them: "a", "a and b", or "a, b, and
// c", with the serial comma.
func listOf(items []string) string {
	switch len(items) {
	case 0, 1:
		return strings.Join(items, "")
	case 2:
		return items[0] + " and " + items[1]
	}
	return strings.Join(items[:len(items)-1], ", ") + ", and " + items[len(items)-1]
}
