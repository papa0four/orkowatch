// internal/security/audit/view.go

package audit

import (
	"strings"
	"time"

	"github.com/papa0four/orkowatch/internal/dataset"
	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/security/finding"
)

type (
	// View is the serializable projection of a completed Result, filtered
	// to findings at or above minSeverity. It is the single shape JSON,
	// YAML, and WriteText all render from.
	View struct {
		Timestamp          string                    `json:"timestamp" yaml:"timestamp"`
		Duration           string                    `json:"duration" yaml:"duration"`
		MinSeverity        string                    `json:"min_severity,omitempty" yaml:"min_severity,omitempty"`
		SystemInfo         *osfingerprint.SystemView `json:"system_info,omitempty" yaml:"system_info,omitempty"`
		Results            []CheckView               `json:"results" yaml:"results"`
		Summary            Summary                   `json:"summary" yaml:"summary"`
		FindingsSuppressed int                       `json:"findings_suppressed,omitempty" yaml:"findings_suppressed,omitempty"`
		MinSeverityApplied string                    `json:"min_severity_applied,omitempty" yaml:"min_severity_applied,omitempty"`
		ReferenceCWEs      []string                  `json:"reference_cwes,omitempty" yaml:"reference_cwes,omitempty"`

		// KnownExploited is the data each finding's count of
		// known-exploited vulnerabilities in its weakness class was read
		// from, or why none was.
		KnownExploited *dataset.Use `json:"known_exploited_data,omitempty" yaml:"known_exploited_data,omitempty"`

		// Operator is what the audit's run, elevated, did with the
		// operator's datasets when it opened its store. It is the run's
		// fact, so the audit command sets it on its own report and the View
		// of a Result never does: under all, the run states it once.
		Operator *dataset.Operator `json:"operator,omitempty" yaml:"operator,omitempty"`
	}

	// CheckView is the serializable projection of a single check's result.
	// Key is the check's short name, as --skip-checks and the rule keys spell
	// it; Name is its long display name. Reason is present whenever Result is
	// neither pass nor fail. Duration is empty for a check that did not
	// run.
	CheckView struct {
		Key         string          `json:"key" yaml:"key"`
		Name        string          `json:"name" yaml:"name"`
		Result      finding.Result  `json:"result" yaml:"result"`
		Reason      string          `json:"reason,omitempty" yaml:"reason,omitempty"`
		Description string          `json:"description" yaml:"description"`
		Duration    string          `json:"duration,omitempty" yaml:"duration,omitempty"`
		Conditions  []ConditionView `json:"conditions,omitempty" yaml:"conditions,omitempty"`
		Details     []string        `json:"details,omitempty" yaml:"details,omitempty"`
	}

	// ConditionView is the serializable projection of one evaluated rule.
	// Evidence sits beside the finding it caused, so a consumer associates
	// the two without parsing headings out of free text.
	ConditionView struct {
		Key      string             `json:"key" yaml:"key"`
		Result   finding.Result     `json:"result" yaml:"result"`
		Reason   string             `json:"reason,omitempty" yaml:"reason,omitempty"`
		Finding  *FindingView       `json:"finding,omitempty" yaml:"finding,omitempty"`
		Evidence []finding.Evidence `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	}

	// FindingView is the serializable projection of a condition's registry
	// description.
	FindingView struct {
		Title       string              `json:"title" yaml:"title"`
		Severity    string              `json:"severity" yaml:"severity"`
		Categories  []string            `json:"categories,omitempty" yaml:"categories,omitempty"`
		Description string              `json:"description,omitempty" yaml:"description,omitempty"`
		Impact      string              `json:"impact,omitempty" yaml:"impact,omitempty"`
		Resolution  string              `json:"resolution,omitempty" yaml:"resolution,omitempty"`
		References  []finding.Reference `json:"references,omitempty" yaml:"references,omitempty"`
		Attack      []finding.Technique `json:"attack,omitempty" yaml:"attack,omitempty"`

		// Weakness is the CWE entry the finding maps to. NoWeakness says why
		// none does, when the registry records that none fits. CVSS is the
		// registry's baseline for the condition, labeled as such, and Host
		// how the condition scores on this host and why, which Severity
		// follows when the host's evidence modified the score.
		Weakness   *finding.Weakness  `json:"weakness,omitempty" yaml:"weakness,omitempty"`
		NoWeakness string             `json:"no_weakness,omitempty" yaml:"no_weakness,omitempty"`
		CVSS       *finding.CVSSScore `json:"cvss,omitempty" yaml:"cvss,omitempty"`
		Host       *finding.HostScore `json:"host_score,omitempty" yaml:"host_score,omitempty"`

		// KnownExploitedInClass is how many vulnerabilities known to be
		// exploited are of the finding's weakness class: a statement about
		// the class, not about this host. It is absent where there are none
		// or they were not read.
		KnownExploitedInClass int `json:"known_exploited_in_class,omitempty" yaml:"known_exploited_in_class,omitempty"`
	}
)

// View returns r's serializable projection. A failed condition whose finding
// falls below minSeverity is left out whole, evidence included, and counted
// as suppressed. Severity is a property of findings, so every other
// condition is projected whatever the threshold: a rule that passed, did not
// apply or could not be evaluated is not a judgment being filtered.
func (r *Result) View(minSeverity string) View {
	v := View{
		Timestamp:      r.StartTime.UTC().Format(time.RFC3339),
		Duration:       r.Duration.String(),
		MinSeverity:    strings.ToUpper(minSeverity),
		Summary:        r.Summary,
		ReferenceCWEs:  r.CWEs,
		KnownExploited: r.KnownExploited,
	}

	if r.HostInfo != nil {
		sv := r.HostInfo.View()
		v.SystemInfo = &sv
	}

	for _, check := range r.Results {
		cv := CheckView{
			Key:         check.Key,
			Name:        check.Name,
			Result:      check.Result,
			Reason:      check.Reason,
			Description: check.Description,
			Details:     check.Details,
		}
		if !check.StartTime.IsZero() {
			cv.Duration = check.Duration.String()
		}

		for _, condition := range check.Conditions {
			view, shown := conditionView(condition, minSeverity, r.classCounts)
			if !shown {
				v.FindingsSuppressed++
				continue
			}
			cv.Conditions = append(cv.Conditions, view)
		}

		v.Results = append(v.Results, cv)
	}

	if v.FindingsSuppressed > 0 {
		v.MinSeverityApplied = strings.ToUpper(minSeverity)
	}

	return v
}

// conditionView projects one condition, reporting false when it is a
// finding the severity threshold suppresses. A finding with a weakness is
// given its class's count from counts, when there are counts.
func conditionView(condition finding.Condition, minSeverity string, counts ClassCounts) (ConditionView, bool) {
	view := ConditionView{
		Key:      condition.Key,
		Result:   condition.Result,
		Reason:   condition.Reason,
		Evidence: condition.Evidence,
	}
	if condition.Finding == nil {
		return view, true
	}

	severity := finding.EffectiveSeverity(*condition.Finding)
	if condition.Result == finding.ResultFail && !finding.MeetsMinSeverity(severity, minSeverity) {
		return ConditionView{}, false
	}

	view.Finding = &FindingView{
		Title:       condition.Finding.Title,
		Severity:    severity,
		Categories:  condition.Finding.Categories,
		Description: condition.Finding.Description,
		Impact:      condition.Finding.Impact,
		Resolution:  condition.Finding.Resolution,
		References:  condition.Finding.References,
		Attack:      condition.Finding.Techniques,
		Weakness:    condition.Finding.Weakness,
		NoWeakness:  condition.Finding.NoWeakness,
		CVSS:        condition.Finding.CVSS,
		Host:        condition.Finding.Host,
	}
	view.Finding.KnownExploitedInClass = classCount(counts, condition.Finding.Weakness)
	return view, true
}

// classCount is how many vulnerabilities known to be exploited counts gives
// the weakness w's class: none for a finding with no weakness or when there
// are no counts. A result's view and a recounted view count by it alike.
func classCount(counts ClassCounts, w *finding.Weakness) int {
	if w == nil || counts == nil {
		return 0
	}
	return counts.ClassCount(string(w.ID))
}

// Recounted is the view with each finding's count of known-exploited
// vulnerabilities in its weakness class taken from counts and the data they
// were read from, or why none was, as when a saved report is matched again
// after the catalog is refreshed. The view it is made from is not changed:
// its checks, conditions, and findings are copied before they are counted.
func (v View) Recounted(counts ClassCounts, use dataset.Use) View {
	v.KnownExploited = &use
	results := make([]CheckView, len(v.Results))
	for i, check := range v.Results {
		conditions := make([]ConditionView, len(check.Conditions))
		for j, condition := range check.Conditions {
			if condition.Finding != nil {
				counted := *condition.Finding
				counted.KnownExploitedInClass = classCount(counts, counted.Weakness)
				condition.Finding = &counted
			}
			conditions[j] = condition
		}
		check.Conditions = conditions
		results[i] = check
	}
	v.Results = results
	return v
}
