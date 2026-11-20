// internal/security/checker/finding.go

package checker

import (
	"fmt"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
)

// report accumulates one check's outcome: a condition per rule the check
// evaluated, and the narration that belongs to none of them. It is the single
// path by which a checker records a result, so a rule is concluded once
// however many subjects tripped it, and a check's own result is always the
// aggregate of its conditions.
type report struct {
	osCtx  registry.OSContext
	result finding.AuditResult
	index  map[registry.FindingKey]int
}

func newReport(id checkIdentity) *report {
	return &report{
		osCtx: id.osCtx,
		result: finding.AuditResult{
			Name:        id.Name(),
			Description: id.Description(),
		},
		index: make(map[registry.FindingKey]int),
	}
}

// note appends one line of narration: what the check did or saw that is not
// the outcome of any rule.
func (r *report) note(symbol, format string, args ...any) {
	r.result.Details = append(r.result.Details, symbol+" "+fmt.Sprintf(format, args...))
}

// section starts a titled block of narration.
func (r *report) section(title string) {
	r.result.Details = append(r.result.Details, "", title)
}

// lines appends narration a tool produced, verbatim.
func (r *report) lines(lines ...string) {
	r.result.Details = append(r.result.Details, lines...)
}

// observed records that the condition key defines was seen on the subjects
// in evidence. The definition decides what that means: fail for most, and
// notapplicable for one describing a state the rule does not cover. A key
// with no definition is a defect in the checker or the data file, not a host
// condition, so it panics rather than letting a detected condition report
// clean. Evidence carrying a kind or fact the definition does not declare
// panics for the same reason: the rules that read the evidence would no longer
// match what the checker records. The empty key is ignored, as pass ignores
// it: the platform defines no rule for the condition.
func (r *report) observed(key registry.FindingKey, evidence ...finding.Evidence) {
	if key == "" {
		return
	}
	def, ok := registry.Lookup(r.osCtx, key)
	if !ok {
		panic("checker: no registry definition for finding key " + string(key) + " on platform " + string(r.osCtx.Platform))
	}
	for _, subject := range evidence {
		if err := def.CheckEvidence(subject); err != nil {
			panic("checker: finding key " + string(key) + ": " + err.Error())
		}
	}

	if i, ok := r.index[key]; ok && r.result.Conditions[i].Finding != nil {
		r.result.Conditions[i].Evidence = append(r.result.Conditions[i].Evidence, evidence...)
		return
	}

	condition := finding.Condition{
		Key:      string(key),
		Result:   def.Result,
		Finding:  def.Finding(),
		Evidence: evidence,
	}
	if def.Result.NeedsReason() {
		condition.Reason = def.Title
	}
	r.record(key, condition)
}

// pass records that each rule was evaluated and holds. A rule already
// concluded otherwise keeps that conclusion. The empty key is ignored, which
// is how a platform that defines no rule for a condition opts out of it.
func (r *report) pass(keys ...registry.FindingKey) {
	for _, key := range keys {
		r.record(key, finding.Condition{Key: string(key), Result: finding.ResultPass})
	}
}

// inconclusive records that each rule produced no judgment, and why. The
// reason is mandatory: a result that is neither pass nor fail tells the
// operator nothing without it, so omitting one is a defect in the checker.
func (r *report) inconclusive(result finding.Result, reason string, keys ...registry.FindingKey) {
	if !result.NeedsReason() || reason == "" {
		panic("checker: inconclusive result " + string(result) + " recorded without a reason")
	}
	for _, key := range keys {
		r.record(key, finding.Condition{Key: string(key), Result: result, Reason: reason})
	}
}

// record merges condition into the rule's standing conclusion. The result
// higher in precedence wins, so the order in which a checker reaches its
// conclusions does not change what it reports.
func (r *report) record(key registry.FindingKey, condition finding.Condition) {
	if key == "" {
		return
	}

	i, ok := r.index[key]
	if !ok {
		r.index[key] = len(r.result.Conditions)
		r.result.Conditions = append(r.result.Conditions, condition)
		return
	}

	standing := &r.result.Conditions[i]
	switch {
	case condition.Result.Outranks(standing.Result):
		*standing = condition
	case condition.Result == standing.Result:
		standing.Evidence = append(standing.Evidence, condition.Evidence...)
	}
}

// finish scores each finding on this host and derives the check's result from
// its conditions. Scoring waits until here because a condition's evidence is
// complete only once the checker stops recording: a finding scored when first
// observed would be scored on part of its subjects.
func (r *report) finish() finding.AuditResult {
	for i := range r.result.Conditions {
		condition := &r.result.Conditions[i]
		if condition.Finding == nil {
			continue
		}
		def, _ := registry.Lookup(r.osCtx, registry.FindingKey(condition.Key))
		condition.Finding.Host = def.Environmental(condition.Evidence)
	}
	r.result.Conclude()
	return r.result
}

// fact records one observation. An empty value records nothing, so a caller
// can pass an observation that may not apply without branching.
func fact(name finding.FactName, value string) finding.Fact {
	return finding.Fact{Name: string(name), Value: value}
}

// evidence builds one evidence entry from a subject and the facts observed on
// it, in the order given. A fact with an empty value is omitted.
func evidence(kind finding.EvidenceKind, subject string, facts ...finding.Fact) finding.Evidence {
	entry := finding.Evidence{Kind: string(kind), Subject: subject}
	for _, f := range facts {
		if f.Value != "" {
			entry.Facts = append(entry.Facts, f)
		}
	}
	return entry
}
