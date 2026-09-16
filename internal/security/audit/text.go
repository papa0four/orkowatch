// internal/security/audit/text.go

package audit

import (
	"fmt"
	"io"
	"strings"

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
		Requested:  result.EnrichmentRequested,
		Err:        result.EnrichmentError,
		References: result.References,
		Result:     result.Enrichment,
	}); err != nil {
		return err
	}

	if err := render.SuppressionNotice(w, v.FindingsSuppressed,
		v.Summary.TotalFindings, minSeverity); err != nil {
		return err
	}

	return render.DetailedSummary(w, render.SummaryData{
		TotalChecks:   v.Summary.TotalChecks,
		PassedChecks:  v.Summary.PassedChecks,
		SkippedChecks: v.Summary.SkippedChecks,
		TotalFindings: v.Summary.TotalFindings,
		Shown:         v.Summary.TotalFindings - v.FindingsSuppressed,
		Critical:      v.Summary.CriticalFindings,
		High:          v.Summary.HighFindings,
		Medium:        v.Summary.MediumFindings,
		Low:           v.Summary.LowFindings,
		Duration:      result.Duration,
	})
}

// writeCheck renders one check: its header, then for a check that ran, its
// duration, findings and raw diagnostic output. A skipped check ends after
// the header because it produced nothing else.
func writeCheck(ew *render.ErrWriter, check CheckView, minSeverity string) error {
	ew.Printf("Check: %s\n", check.Name)
	ew.Printf("Status: %s\n", check.Status)
	if check.Description != "" {
		ew.Printf("Description: %s\n", check.Description)
	}
	if check.Status == types.StatusSkipped {
		ew.Printf("\n")
		return ew.Err()
	}
	ew.Printf("Duration: %s\n", check.Duration)

	ew.Printf("Findings:\n")
	if len(check.Findings) == 0 {
		ew.Printf("%s No findings at or above %s severity\n",
			types.SymbolOK, strings.ToUpper(minSeverity))
	}
	for _, finding := range check.Findings {
		if err := writeFinding(ew, finding); err != nil {
			return err
		}
	}

	if len(check.Details) > 0 {
		ew.Printf("Raw Diagnostic Output:\n")
		writeDetails(ew, check.Details)
	}

	ew.Printf("\n")
	return ew.Err()
}

// writeFinding renders one finding as its severity line followed by each
// populated field, indented beneath it.
func writeFinding(ew *render.ErrWriter, finding FindingView) error {
	if err := render.FindingLine(ew, "", finding.Severity, finding.Title); err != nil {
		return err
	}
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
	return ew.Err()
}

// writeDetails renders a check's raw diagnostic lines. An empty detail is a
// section break the checker placed deliberately and is written as a blank
// line rather than an indented empty one.
func writeDetails(ew *render.ErrWriter, details []string) {
	for _, detail := range details {
		if detail == "" {
			ew.Printf("\n")
			continue
		}
		ew.Printf("  %s\n", detail)
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
