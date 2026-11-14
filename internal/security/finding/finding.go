// internal/security/finding/finding.go

// Package finding defines the vocabulary shared by every checker, renderer, and
// report: the check, condition, finding and evidence shapes, the result and
// severity values that appear in output, and CWE identifiers. The result and
// severity values are output contract values.
package finding

import (
	"strings"
	"time"
)

// Display symbols shared by every checker and renderer.
const (
	// SymbolOK prefixes lines reporting a passing condition.
	SymbolOK = "[+]"
	// SymbolError prefixes lines reporting a check execution failure.
	SymbolError = "[-]"
	// SymbolWarning prefixes lines reporting a non-critical finding.
	SymbolWarning = "[!]"
	// SymbolInfo prefixes informational lines carrying no judgment.
	SymbolInfo = "[*]"
	// SymbolCritical prefixes lines reporting a critical finding.
	SymbolCritical = "[X]"
)

// The qualitative severity rating scale of CVSS v3.1 section 5, in ascending
// rank order. Definitions carry CVSS vectors, so this scale is the anchor
// rather than XCCDF's own severity enumeration, which has no critical.
const (
	// SeverityNone is the rating of a 0.0 score: a recorded condition with
	// no impact.
	SeverityNone = "NONE"
	// SeverityLow is the second severity rank.
	SeverityLow = "LOW"
	// SeverityMedium is the third severity rank.
	SeverityMedium = "MEDIUM"
	// SeverityHigh is the fourth severity rank.
	SeverityHigh = "HIGH"
	// SeverityCritical is the highest severity rank.
	SeverityCritical = "CRITICAL"
)

// The XCCDF 1.2 resultEnumType values a condition or check can report,
// serialized in the schema's lowercase spelling. fixed is absent because
// owatch does not remediate.
const (
	// ResultPass means the condition was evaluated and holds.
	ResultPass Result = "pass"
	// ResultFail means the condition was evaluated and does not hold.
	ResultFail Result = "fail"
	// ResultError means the evaluation could not complete, as when a run
	// lacks the privilege to gather what it needs.
	ResultError Result = "error"
	// ResultUnknown means the evaluation ran and its outcome could not be
	// interpreted, as when no parser recognizes a tool's output.
	ResultUnknown Result = "unknown"
	// ResultNotApplicable means the condition does not apply to the subject
	// it was evaluated against.
	ResultNotApplicable Result = "notapplicable"
	// ResultNotChecked means nothing evaluated the condition.
	ResultNotChecked Result = "notchecked"
	// ResultNotSelected means the operator excluded the condition from the
	// run.
	ResultNotSelected Result = "notselected"
	// ResultInformational means the condition records a fact rather than a
	// compliance judgment.
	ResultInformational Result = "informational"
)

type (
	// Result is the outcome of evaluating a condition, or the aggregate
	// outcome of a check's conditions.
	Result string

	// AuditResult is one check's outcome. Result and Reason are derived from
	// Conditions by Conclude; Details holds narration that belongs to no
	// condition.
	AuditResult struct {
		Name        string
		Description string
		Result      Result
		Reason      string
		Conditions  []Condition
		Details     []string
		StartTime   time.Time
		EndTime     time.Time
		Duration    time.Duration
	}

	// Condition is one rule a check evaluated and what it concluded. Key is
	// the rule's stable identifier, the registry finding key. Reason states
	// why Result is anything other than pass or fail. Finding is the
	// registry's description of the condition, present when the rule did
	// not hold or does not apply; Evidence names the subjects that caused
	// the result.
	Condition struct {
		Key      string
		Result   Result
		Reason   string
		Finding  *Finding
		Evidence []Evidence
	}

	// Finding is the registry's description of a condition.
	Finding struct {
		Title       string
		Description string
		Severity    string
		CWE         CWE
		Categories  []string
		Impact      string
		Resolution  string
		References  []Reference
	}

	// Evidence is one subject a condition was evaluated against and what
	// was observed about it. Kind names what sort of thing Subject is, and
	// Facts are the observations in the order the checker recorded them.
	// One shape serves every checker.
	Evidence struct {
		Kind    string `json:"kind" yaml:"kind"`
		Subject string `json:"subject" yaml:"subject"`
		Facts   []Fact `json:"facts,omitempty" yaml:"facts,omitempty"`
	}

	// Fact is one named observation about an evidence subject.
	Fact struct {
		Name  string `json:"name" yaml:"name"`
		Value string `json:"value" yaml:"value"`
	}

	// Reference provides additional information about a finding
	Reference struct {
		Title string `json:"title" yaml:"title"`
		URL   string `json:"url,omitempty" yaml:"url,omitempty"`
		Type  string `json:"type" yaml:"type"` // e.g., "CVE", "CWE", "NIST", "MITRE", etc.
	}
)

var (
	// severityRank lists the canonical severity values in ascending rank
	// order. SeverityLevel, NormalizeSeverity, and SeverityNames all derive
	// from it, so the canonical set is enumerated once.
	severityRank = []string{SeverityNone, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

	// resultPrecedence orders results from the one that most demands
	// attention to the one that least does. A check reports the first of
	// these any of its conditions holds: one failed condition makes the
	// check a failure however many others passed, and a condition that
	// could not be evaluated outranks every one that could and held.
	resultPrecedence = []Result{
		ResultFail,
		ResultError,
		ResultUnknown,
		ResultPass,
		ResultInformational,
		ResultNotApplicable,
		ResultNotChecked,
		ResultNotSelected,
	}
)

// Results returns every result value in precedence order, for renderers and
// counters that enumerate the set.
func Results() []Result {
	return append([]Result(nil), resultPrecedence...)
}

// Outranks reports whether r takes precedence over other when two results
// for the same rule or check are combined.
func (r Result) Outranks(other Result) bool {
	for _, result := range resultPrecedence {
		switch result {
		case r:
			return r != other
		case other:
			return false
		}
	}
	return false
}

// NeedsReason reports whether a result must state why it was reached. pass
// and fail speak for themselves; every other value describes an evaluation
// that did not produce a judgment.
func (r Result) NeedsReason() bool {
	return r != ResultPass && r != ResultFail
}

// Conclude derives the check's result from its conditions: the highest in
// precedence any of them holds, with that condition's reason. A check with
// no conditions evaluated nothing and reports notchecked.
func (r *AuditResult) Conclude() {
	if len(r.Conditions) == 0 {
		r.Result = ResultNotChecked
		r.Reason = "the check evaluated no conditions"
		return
	}

	lead := r.Conditions[0]
	for _, condition := range r.Conditions[1:] {
		if condition.Result.Outranks(lead.Result) {
			lead = condition
		}
	}
	r.Result = lead.Result
	r.Reason = lead.Reason
}

// SeverityLevel returns the numeric rank of a severity string for threshold
// comparisons. Unknown values return -1 so they are never silently dropped.
func SeverityLevel(s string) int {
	upper := strings.ToUpper(s)
	for rank, name := range severityRank {
		if name == upper {
			return rank
		}
	}
	return -1
}

// NormalizeSeverity upper-case severity and reports whether it is canonical
func NormalizeSeverity(severity string) (string, bool) {
	upper := strings.ToUpper(severity)
	return upper, SeverityLevel(upper) >= 0
}

// Severities returns the canonical severity values in ascending rank order.
func Severities() []string {
	return append([]string(nil), severityRank...)
}

// SeverityNames returns the canonical severity values in ascending rank order
// for operator-facing messages
func SeverityNames() string {
	return strings.Join(severityRank, ", ")
}

// MeetsMinSeverity reports whether findingSeverity is at or above the min
// threshold. Unrecognized severity values pass through so findings are
// never silently dropped.
func MeetsMinSeverity(findingSeverity, min string) bool {
	fl := SeverityLevel(findingSeverity)
	ml := SeverityLevel(min)
	if fl < 0 || ml < 0 {
		return true
	}
	return fl >= ml
}

// EffectiveSeverity returns the severity value used for filtering and
// display. It currently always returns the finding's static registry-
// assigned severity. Once per-finding CVE/CVSS enrichment lands, this is
// the single point where a live CVSS-derived severity would override the
// static value. Callers should go through this rather than reading
// finding.Severity directly, so severity sourcing only has to change here.
func EffectiveSeverity(f Finding) string {
	return f.Severity
}

// SeverityFormat returns the display symbol and fixed-width padded severity label
func SeverityFormat(severity string) (symbol, label string) {
	switch strings.ToUpper(severity) {
	case SeverityCritical:
		return SymbolCritical, "CRITICAL"
	case SeverityHigh:
		return SymbolWarning, "HIGH    "
	case SeverityMedium:
		return SymbolWarning, "MEDIUM  "
	case SeverityLow:
		return SymbolInfo, "LOW     "
	case SeverityNone:
		return SymbolInfo, "NONE    "
	default:
		return SymbolInfo, severity
	}
}
