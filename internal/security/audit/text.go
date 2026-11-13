// internal/security/audit/text.go

package audit

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/security/enrichment"
	"github.com/papa0four/orkowatch/internal/security/types"
)

// WriteText renders a completed audit as text: each check with its
// findings, the enrichment block, suppression notice, and summary. It does
// not render the system block; callers write that separately via
// osfingerprint.WriteText. The first write error, if any, is returned.
func WriteText(w io.Writer, result *Result, minSeverity string) error {
	if result == nil {
		return fmt.Errorf("audit: cannot render nil Result")
	}

	v := result.View(minSeverity)
	ew := render.NewErrWriter(w)

	for _, check := range v.Results {
		if err := writeCheck(ew, check, minSeverity); err != nil {
			return err
		}
	}

	if err := enrichment.Block(w, enrichment.Data{
		Requested: result.EnrichmentRequested,
		Err:       result.EnrichmentError,
		CWEs:      result.CWEs,
		Result:    result.Enrichment,
	}); err != nil {
		return err
	}

	if err := render.SuppressionNotice(w, v.FindingsSuppressed,
		v.Summary.TotalFindings, minSeverity); err != nil {
		return err
	}

	writeSummary(ew, v, result.Duration)
	return ew.Err()
}

// writeCheck renders one check: its header, then for a check that ran, its
// duration, findings, the remaining conditions and its narration. A check
// that was not selected ends after the header because it produced nothing
// else. Result values are shown in upper case here; the canonical lowercase
// spelling belongs to the structured encodings.
func writeCheck(ew *render.ErrWriter, check CheckView, minSeverity string) error {
	ew.Printf("Check: %s\n", check.Name)
	ew.Printf("Result: %s\n", strings.ToUpper(string(check.Result)))
	if check.Reason != "" {
		ew.Printf("Reason: %s\n", render.HostText(check.Reason))
	}
	if check.Description != "" {
		ew.Printf("Description: %s\n", check.Description)
	}
	if check.Result == types.ResultNotSelected {
		ew.Printf("\n")
		return ew.Err()
	}
	ew.Printf("Duration: %s\n", check.Duration)

	var findings, others []ConditionView
	for _, condition := range check.Conditions {
		if condition.Result == types.ResultFail && condition.Finding != nil {
			findings = append(findings, condition)
			continue
		}
		others = append(others, condition)
	}

	ew.Printf("Findings:\n")
	if len(findings) == 0 {
		ew.Printf("%s No findings at or above %s severity\n",
			types.SymbolOK, strings.ToUpper(minSeverity))
	}
	for _, condition := range findings {
		if err := writeFinding(ew, condition); err != nil {
			return err
		}
	}

	if len(others) > 0 {
		ew.Printf("Other Conditions:\n")
		for _, condition := range others {
			if err := writeCondition(ew, condition); err != nil {
				return err
			}
		}
	}

	if len(check.Details) > 0 {
		ew.Printf("Raw Diagnostic Output:\n")
		writeDetails(ew, check.Details)
	}

	ew.Printf("\n")
	return ew.Err()
}

// writeFinding renders a failed condition as its severity line followed by
// the rule it failed, each populated field of the finding, and the evidence
// that caused it, indented beneath.
func writeFinding(ew *render.ErrWriter, condition ConditionView) error {
	finding := condition.Finding
	if err := render.FindingLine(ew, "", finding.Severity, finding.Title); err != nil {
		return err
	}
	ew.Printf("  Rule: %s\n", condition.Key)
	if len(finding.Categories) > 0 {
		ew.Printf("  Categories: %s\n", strings.Join(finding.Categories, ", "))
	}
	if finding.Description != "" {
		ew.Printf("  Description: %s\n", finding.Description)
	}
	if finding.Impact != "" {
		ew.Printf("  Impact: %s\n", finding.Impact)
	}
	if finding.Resolution != "" {
		ew.Printf("  Resolution: %s\n", finding.Resolution)
	}
	if len(finding.References) > 0 {
		ew.Printf("  References:\n")
		for _, ref := range finding.References {
			writeReference(ew, ref)
		}
	}
	return writeEvidence(ew, "  ", condition.Evidence)
}

// writeCondition renders a condition that is not a finding as one line: its
// result, its rule, and the reason when the result needs one. Evidence
// follows for a condition that recorded any, as one that does not apply to
// the subjects it names.
func writeCondition(ew *render.ErrWriter, condition ConditionView) error {
	symbol := types.SymbolInfo
	if condition.Result == types.ResultPass {
		symbol = types.SymbolOK
	}

	ew.Printf("  %s %-13s  %s", symbol, strings.ToUpper(string(condition.Result)), condition.Key)
	if condition.Reason != "" {
		ew.Printf(": %s", render.HostText(condition.Reason))
	}
	ew.Printf("\n")
	return writeEvidence(ew, "    ", condition.Evidence)
}

// writeEvidence renders the subjects a condition was concluded on.
func writeEvidence(ew *render.ErrWriter, indent string, evidence []types.Evidence) error {
	if len(evidence) == 0 {
		return ew.Err()
	}
	ew.Printf("%sEvidence (%d):\n", indent, len(evidence))
	for _, entry := range evidence {
		if err := render.EvidenceLine(ew, indent+"  ", entry); err != nil {
			return err
		}
	}
	return ew.Err()
}

// writeDetails renders a check's narration. An empty detail is a section
// break the checker placed deliberately and is written as a blank line
// rather than an indented empty one. Narration can quote what a tool
// printed, so each line passes through render.HostText.
func writeDetails(ew *render.ErrWriter, details []string) {
	for _, detail := range details {
		if detail == "" {
			ew.Printf("\n")
			continue
		}
		ew.Printf("  %s\n", render.HostText(detail))
	}
}

// writeReference writes a single reference as "Type: Title", appending the
// URL in parentheses when it differs from Title. registry.classifyReference
// always sets Title to the human- or ID-readable form and sets URL only
// when a distinct link exists, so the two are never printed twice.
func writeReference(ew *render.ErrWriter, ref types.Reference) {
	if ref.URL != "" && ref.URL != ref.Title {
		ew.Printf("    %s: %s (%s)\n", ref.Type, ref.Title, ref.URL)
		return
	}
	ew.Printf("    %s: %s\n", ref.Type, ref.Title)
}

// writeSummary renders the summary block: checks and conditions broken down
// by result, findings by severity. Results that did not occur are left out;
// every severity is printed, so a zero is stated rather than implied.
func writeSummary(ew *render.ErrWriter, v View, duration time.Duration) {
	ew.Printf("Summary:\n")
	ew.Printf("Total Checks:      %d\n", v.Summary.TotalChecks)
	writeResultCounts(ew, v.Summary.Checks)
	ew.Printf("Total Conditions:  %d\n", v.Summary.TotalConditions)
	writeResultCounts(ew, v.Summary.Conditions)

	if v.FindingsSuppressed > 0 {
		ew.Printf("Total Findings:    %d (%d present, %d suppressed)\n",
			v.Summary.TotalFindings, v.Summary.TotalFindings-v.FindingsSuppressed, v.FindingsSuppressed)
	} else {
		ew.Printf("Total Findings:    %d\n", v.Summary.TotalFindings)
	}

	severities := types.Severities()
	for i := len(severities) - 1; i >= 0; i-- {
		label := severities[i][:1] + strings.ToLower(severities[i][1:]) + ":"
		ew.Printf("  %-15s  %d\n", label, v.Summary.Findings[severities[i]])
	}
	ew.Printf("Duration:          %v\n", duration)
}

// writeResultCounts renders one count per result that occurred, in
// precedence order.
func writeResultCounts(ew *render.ErrWriter, counts map[types.Result]int) {
	for _, result := range types.Results() {
		if count := counts[result]; count > 0 {
			ew.Printf("  %-15s  %d\n", string(result)+":", count)
		}
	}
}
