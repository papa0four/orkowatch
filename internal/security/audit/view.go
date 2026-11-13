// internal/security/audit/view.go

package audit

import (
	"strings"
	"time"

	"github.com/papa0four/orkowatch/internal/osfingerprint"
	"github.com/papa0four/orkowatch/internal/security/enrichment"
	"github.com/papa0four/orkowatch/internal/security/types"
)

type (
	// View is the serializable projection of a completed Result, filtered
	// to findings at or above minSeverity. It is the single shape JSON,
	// YAML, and WriteText all render from.
	View struct {
		Timestamp           string                    `json:"timestamp" yaml:"timestamp"`
		Duration            string                    `json:"duration" yaml:"duration"`
		SystemInfo          *osfingerprint.SystemView `json:"system_info,omitempty" yaml:"system_info,omitempty"`
		Results             []CheckView               `json:"results" yaml:"results"`
		Summary             Summary                   `json:"summary" yaml:"summary"`
		FindingsSuppressed  int                       `json:"findings_suppressed,omitempty" yaml:"findings_suppressed,omitempty"`
		MinSeverityApplied  string                    `json:"min_severity_applied,omitempty" yaml:"min_severity_applied,omitempty"`
		EnrichmentRequested bool                      `json:"enrichment_requested" yaml:"enrichment_requested"`
		EnrichmentError     string                    `json:"enrichment_error,omitempty" yaml:"enrichment_error,omitempty"`
		ReferenceCWEs       []string                  `json:"reference_cwes,omitempty" yaml:"reference_cwes,omitempty"`
		Entries             []enrichment.EntryView    `json:"enrichment_entries,omitempty" yaml:"enrichment_entries,omitempty"`
		Failures            []enrichment.FailureView  `json:"enrichment_failures,omitempty" yaml:"enrichment_failures,omitempty"`
	}

	// CheckView is the serializable projection of a single check's result.
	// Reason is present whenever Result is neither pass nor fail. Duration
	// is empty for a check that was not selected.
	CheckView struct {
		Name        string          `json:"name" yaml:"name"`
		Result      types.Result    `json:"result" yaml:"result"`
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
		Key      string           `json:"key" yaml:"key"`
		Result   types.Result     `json:"result" yaml:"result"`
		Reason   string           `json:"reason,omitempty" yaml:"reason,omitempty"`
		Finding  *FindingView     `json:"finding,omitempty" yaml:"finding,omitempty"`
		Evidence []types.Evidence `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	}

	// FindingView is the serializable projection of a condition's registry
	// description.
	FindingView struct {
		Title       string            `json:"title" yaml:"title"`
		Severity    string            `json:"severity" yaml:"severity"`
		Categories  []string          `json:"categories,omitempty" yaml:"categories,omitempty"`
		Description string            `json:"description,omitempty" yaml:"description,omitempty"`
		Impact      string            `json:"impact,omitempty" yaml:"impact,omitempty"`
		Resolution  string            `json:"resolution,omitempty" yaml:"resolution,omitempty"`
		References  []types.Reference `json:"references,omitempty" yaml:"references,omitempty"`
	}
)

// View returns r's serializable projection. A failed condition whose finding
// falls below minSeverity is left out whole, evidence included, and counted
// as suppressed. Severity is a property of findings, so every other
// condition is projected whatever the threshold: a rule that passed, did not
// apply or could not be evaluated is not a judgment being filtered.
func (r *Result) View(minSeverity string) View {
	v := View{
		Timestamp:           r.StartTime.UTC().Format(time.RFC3339),
		Duration:            r.Duration.String(),
		Summary:             r.Summary,
		EnrichmentRequested: r.EnrichmentRequested,
		ReferenceCWEs:       r.CWEs,
	}

	if r.HostInfo != nil {
		sv := r.HostInfo.View()
		v.SystemInfo = &sv
	}

	if r.EnrichmentError != nil {
		v.EnrichmentError = r.EnrichmentError.Error()
	}
	v.Entries = enrichment.Entries(r.CWEs, r.Enrichment)
	v.Failures = enrichment.Failures(r.Enrichment)

	for _, check := range r.Results {
		cv := CheckView{
			Name:        check.Name,
			Result:      check.Result,
			Reason:      check.Reason,
			Description: check.Description,
			Details:     check.Details,
		}
		if check.Result != types.ResultNotSelected {
			cv.Duration = check.Duration.String()
		}

		for _, condition := range check.Conditions {
			view, shown := conditionView(condition, minSeverity)
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
// finding the severity threshold suppresses.
func conditionView(condition types.Condition, minSeverity string) (ConditionView, bool) {
	view := ConditionView{
		Key:      condition.Key,
		Result:   condition.Result,
		Reason:   condition.Reason,
		Evidence: condition.Evidence,
	}
	if condition.Finding == nil {
		return view, true
	}

	severity := types.EffectiveSeverity(*condition.Finding)
	if condition.Result == types.ResultFail && !types.MeetsMinSeverity(severity, minSeverity) {
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
	}
	return view, true
}
