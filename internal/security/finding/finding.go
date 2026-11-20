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

// The qualitative severity rating scale of CVSS v3.1 section 5, which CVSS v4.0
// keeps as its Table 22, in ascending
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
	// condition. Key is the check's canonical short name, the one
	// --skip-checks and the rule keys use, which the audit sets because a
	// checker does not know where it sits in the run; Name is the checker's
	// own long display name.
	AuditResult struct {
		Key         string
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
		Weakness    *Weakness
		NoWeakness  string
		CVSS        *CVSSScore
		Host        *HostScore
		Categories  []string
		Impact      string
		Resolution  string
		References  []Reference
		Techniques  []Technique
	}

	// Weakness is the CWE entry a finding maps to, as MITRE's catalog states
	// it. Usage is MITRE's own guidance on mapping to the entry.
	Weakness struct {
		ID          CWE    `json:"id" yaml:"id"`
		Name        string `json:"name" yaml:"name"`
		Description string `json:"description" yaml:"description"`
		Usage       string `json:"mapping_usage" yaml:"mapping_usage"`
		URL         string `json:"url" yaml:"url"`
	}

	// CVSSScore is one CVSS score with what it states about itself: the
	// version, the vector it came from, whose it is, and which FIRST
	// nomenclature label applies to it (CVSS-B for a base score, CVSS-BE for
	// one modified by the host's evidence). Basis says what the score is a
	// statement about, so a baseline for a condition is not mistaken for a
	// measurement of one host.
	CVSSScore struct {
		Version      string  `json:"version" yaml:"version"`
		Vector       string  `json:"vector" yaml:"vector"`
		Score        float64 `json:"score" yaml:"score"`
		Severity     string  `json:"severity" yaml:"severity"`
		Source       string  `json:"source" yaml:"source"`
		Nomenclature string  `json:"nomenclature" yaml:"nomenclature"`
		Basis        string  `json:"basis" yaml:"basis"`

		// CalculatorURL opens FIRST's calculator on the vector, so a reader can
		// reproduce the score there. It is a link and owatch does not follow it.
		CalculatorURL string `json:"calculator_url,omitempty" yaml:"calculator_url,omitempty"`
	}

	// HostScore is how a finding scores on the host it was raised on. Every
	// rule of its definition is accounted for: Modified holds the metrics the
	// evidence set, and Unmodified each metric it left at the baseline's
	// value, with why. CVSS is the CVSS-BE score, nil when no rule set a
	// metric, because a score is labelled with E only when an Environmental
	// metric was used to compute it; the baseline then stands.
	HostScore struct {
		CVSS       *CVSSScore         `json:"cvss,omitempty" yaml:"cvss,omitempty"`
		Modified   []ModifiedMetric   `json:"modified,omitempty" yaml:"modified,omitempty"`
		Unmodified []UnmodifiedMetric `json:"unmodified,omitempty" yaml:"unmodified,omitempty"`
	}

	// ModifiedMetric is a Modified Base metric a registry rule derived from a
	// fact a checker recorded on the host, with the passage of FIRST's
	// Implementation Guide the rule rests on. Carried is how many of the
	// rule's Subjects recorded the fact with this value.
	ModifiedMetric struct {
		Metric   string `json:"metric" yaml:"metric"`
		Value    string `json:"value" yaml:"value"`
		Fact     Fact   `json:"fact" yaml:"fact"`
		Because  string `json:"because" yaml:"because"`
		Section  string `json:"guide_section" yaml:"guide_section"`
		Quote    string `json:"guide_quote" yaml:"guide_quote"`
		Carried  int    `json:"subjects_carrying" yaml:"subjects_carrying"`
		Subjects int    `json:"subjects" yaml:"subjects"`
	}

	// UnmodifiedMetric is a Modified Base metric a rule could have set and
	// did not on this host, with the reason, so the baseline's value is traced
	// to what was observed.
	UnmodifiedMetric struct {
		Metric string `json:"metric" yaml:"metric"`
		Reason string `json:"reason" yaml:"reason"`
	}

	// Technique is a MITRE ATT&CK technique an adversary can use because of
	// the condition a finding reports. Tactics are as the ATT&CK site lists
	// them for the technique. Basis states what in MITRE's published data ties
	// the technique to this finding, so the association can be checked.
	Technique struct {
		ID          string       `json:"id" yaml:"id"`
		Name        string       `json:"name" yaml:"name"`
		Tactics     []string     `json:"tactics" yaml:"tactics"`
		URL         string       `json:"url" yaml:"url"`
		Mitigations []Mitigation `json:"mitigations,omitempty" yaml:"mitigations,omitempty"`
		Basis       []string     `json:"basis,omitempty" yaml:"basis,omitempty"`
	}

	// Mitigation is a MITRE ATT&CK mitigation the technique's page lists as
	// addressing it.
	Mitigation struct {
		ID   string `json:"id" yaml:"id"`
		Name string `json:"name" yaml:"name"`
		URL  string `json:"url" yaml:"url"`
	}

	// Evidence is one subject a condition was evaluated against and what
	// was observed about it. Kind names what sort of thing Subject is, and
	// Facts are the observations in the order the checker recorded them.
	// One shape serves every checker.
	Evidence struct {
		Kind    EvidenceKind `json:"kind" yaml:"kind"`
		Subject string       `json:"subject" yaml:"subject"`
		Facts   []Fact       `json:"facts,omitempty" yaml:"facts,omitempty"`
	}

	// Fact is one named observation about an evidence subject.
	Fact struct {
		Name  FactName `json:"name" yaml:"name"`
		Value string   `json:"value" yaml:"value"`
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

// EffectiveSeverity returns the severity used for filtering, counting and
// display: the host score's when the host's evidence modified the finding's
// score, and the registry's baseline otherwise. Callers go through it rather
// than reading Severity, so a finding is never filtered by one severity and
// shown with another.
func EffectiveSeverity(f Finding) string {
	if f.Host != nil && f.Host.CVSS != nil {
		return f.Host.CVSS.Severity
	}
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
