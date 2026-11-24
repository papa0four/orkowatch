// internal/security/audit/text.go

package audit

import (
	"fmt"
	"io"
	"strings"

	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/security/finding"
)

// WriteViewText renders a completed audit as text: each check with its
// findings, the suppression notice, and the summary. It renders
// from the projection a saved report carries, so a live run and a saved report
// show the same text. It does not render the system block; callers write that
// separately via osfingerprint.WriteViewText. The first write error, if any, is
// returned.
func WriteViewText(w io.Writer, v View) error {
	ew := render.NewErrWriter(w)

	// A report written before the view named its threshold carries it only
	// when something was suppressed; with neither, nothing was filtered.
	minSeverity := v.MinSeverity
	if minSeverity == "" {
		minSeverity = v.MinSeverityApplied
	}
	if minSeverity == "" {
		minSeverity = finding.SeverityNone
	}

	for _, check := range v.Results {
		if err := writeCheck(ew, check, minSeverity); err != nil {
			return err
		}
	}

	if err := render.SuppressionNotice(w, v.FindingsSuppressed,
		v.Summary.TotalFindings, minSeverity); err != nil {
		return err
	}

	writeSummary(ew, v)
	return ew.Err()
}

// writeCheck renders one check: its header, then for a check that ran, its
// duration, findings, the remaining conditions and its narration. A check
// that did not run, not selected or with no definitions on the platform, ends
// after the header because it produced nothing else. Result values are shown
// in upper case here; the canonical lowercase spelling belongs to the
// structured encodings.
func writeCheck(ew *render.ErrWriter, check CheckView, minSeverity string) error {
	ew.Printf("Check: %s\n", check.Name)
	ew.Printf("Result: %s\n", strings.ToUpper(string(check.Result)))
	if check.Reason != "" {
		ew.Printf("Reason: %s\n", render.HostText(check.Reason))
	}
	if check.Description != "" {
		ew.Printf("Description: %s\n", check.Description)
	}
	if check.Duration == "" {
		ew.Printf("\n")
		return ew.Err()
	}
	ew.Printf("Duration: %s\n", check.Duration)

	var findings, others []ConditionView
	for _, condition := range check.Conditions {
		if condition.Result == finding.ResultFail && condition.Finding != nil {
			findings = append(findings, condition)
			continue
		}
		others = append(others, condition)
	}

	ew.Printf("Findings:\n")
	if len(findings) == 0 {
		ew.Printf("%s No findings at or above %s severity\n",
			finding.SymbolOK, strings.ToUpper(minSeverity))
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
	def := condition.Finding
	if err := render.FindingLine(ew, "", def.Severity, def.Title); err != nil {
		return err
	}
	ew.Printf("  Rule: %s\n", condition.Key)
	writeWeaknessAndCVSS(ew, def)
	if len(def.Categories) > 0 {
		ew.Printf("  Categories: %s\n", strings.Join(def.Categories, ", "))
	}
	if def.Description != "" {
		ew.Printf("  Description: %s\n", def.Description)
	}
	if def.Impact != "" {
		ew.Printf("  Impact: %s\n", def.Impact)
	}
	if def.Resolution != "" {
		ew.Printf("  Resolution: %s\n", def.Resolution)
	}
	if len(def.References) > 0 {
		ew.Printf("  References:\n")
		for _, ref := range def.References {
			writeReference(ew, ref)
		}
	}
	if len(def.Attack) > 0 {
		ew.Printf("  MITRE ATT&CK:\n")
		for _, technique := range def.Attack {
			ew.Printf("    %s\n", TechniqueText(technique))
			for _, basis := range technique.Basis {
				ew.Printf("      Basis: %s\n", basis)
			}
			if len(technique.Mitigations) > 0 {
				ew.Printf("      Mitigations: %s\n", MitigationsText(technique.Mitigations))
			}
		}
	}
	return writeEvidence(ew, "  ", condition.Evidence)
}

// writeWeaknessAndCVSS writes the lines that say what kind of weakness a
// finding is and how it is scored: the weakness, or why none fits, the
// registry's baseline, and the score on this host with what it rests on.
func writeWeaknessAndCVSS(ew *render.ErrWriter, def *FindingView) {
	if def.Weakness != nil {
		writeLabeled(ew, "Weakness", WeaknessLines(*def.Weakness))
	} else if def.NoWeakness != "" {
		ew.Printf("  Weakness: none. %s\n", def.NoWeakness)
	}
	if def.CVSS == nil {
		return
	}
	writeLabeled(ew, "CVSS baseline", ScoreLines(*def.CVSS))
	writeLabeled(ew, "CVSS on this host", HostScoreLines(def.Host))
}

// writeLabeled writes a block's first line after its label and the lines that
// trace it indented beneath.
func writeLabeled(ew *render.ErrWriter, label string, lines []string) {
	ew.Printf("  %s: %s\n", label, lines[0])
	for _, line := range lines[1:] {
		ew.Printf("    %s\n", line)
	}
}

// writeCondition renders a condition that is not a finding as one line: its
// result, its rule, and the reason when the result needs one. Evidence
// follows for a condition that recorded any, as one that does not apply to
// the subjects it names.
func writeCondition(ew *render.ErrWriter, condition ConditionView) error {
	symbol := finding.SymbolInfo
	if condition.Result == finding.ResultPass {
		symbol = finding.SymbolOK
	}

	ew.Printf("  %s %-13s  %s", symbol, strings.ToUpper(string(condition.Result)), condition.Key)
	if condition.Reason != "" {
		ew.Printf(": %s", render.HostText(condition.Reason))
	}
	ew.Printf("\n")
	return writeEvidence(ew, "    ", condition.Evidence)
}

// writeEvidence renders the subjects a condition was concluded on.
func writeEvidence(ew *render.ErrWriter, indent string, evidence []finding.Evidence) error {
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

// WeaknessLines renders the CWE entry a finding maps to as its identifier and
// name, with MITRE's guidance on mapping to it, then its lineage from the
// broadest entry down to its own. It is shared so every view of a finding names
// its weakness the same way.
func WeaknessLines(w finding.Weakness) []string {
	lines := []string{fmt.Sprintf("%s %s (MITRE mapping usage: %s)", w.ID, w.Name, w.Usage)}
	if len(w.Lineage) == 0 {
		return lines
	}
	for i, a := range w.Lineage {
		step := fmt.Sprintf("%s %s (%s)", a.ID, a.Name, a.Abstraction)
		if i > 0 {
			step = "> " + step
		}
		lines = append(lines, step)
	}
	return append(lines, fmt.Sprintf("> %s %s", w.ID, w.Name))
}

// CVSSText renders a CVSS score with the label FIRST requires on a displayed
// score, the version, the vector and what the score is a statement about.
func CVSSText(s finding.CVSSScore) string {
	return fmt.Sprintf("%.1f %s  %s v%s, %s  %s", s.Score, s.Severity, s.Nomenclature, s.Version, s.Basis, s.Vector)
}

// ScoreLines renders a CVSS score as every view shows it: the labeled score,
// then the link that opens FIRST's calculator on its vector.
func ScoreLines(s finding.CVSSScore) []string {
	lines := []string{CVSSText(s)}
	if s.CalculatorURL != "" {
		lines = append(lines, "calculator: "+s.CalculatorURL)
	}
	return lines
}

// HostScoreLines renders how a finding scores on the host it was raised on, so
// every view states whether its score is the baseline or was modified by the
// host's evidence. The first line is the CVSS-BE score, or why there is none;
// the lines after it trace each Modified Base metric to the fact, the share of
// subjects and the Implementation Guide passage behind it, and give each metric
// left at the baseline with its reason. A nil h is a definition with no rule.
func HostScoreLines(h *finding.HostScore) []string {
	if h == nil {
		return []string{"none; no rule of this finding reads the host, so the CVSS-B baseline is its only score"}
	}
	lines := []string{"none; the evidence recorded on this host modified no metric, so the CVSS-B baseline stands"}
	if h.CVSS != nil {
		lines = ScoreLines(*h.CVSS)
	}
	for _, m := range h.Modified {
		lines = append(lines,
			fmt.Sprintf("%s:%s from %s %s on %d of %s: %s",
				m.Metric, m.Value, m.Fact.Name, render.HostText(m.Fact.Value), m.Carried, render.Count(m.Subjects, "subject", "subjects"), m.Because),
			fmt.Sprintf("  Implementation Guide, %s: \"%s\"", m.Section, m.Quote))
	}
	for _, u := range h.Unmodified {
		lines = append(lines, fmt.Sprintf("%s not modified: %s", u.Metric, render.HostText(u.Reason)))
	}
	return lines
}

// SeverityBasis says what a finding's severity rests on: the CVSS-BE score
// when the host's evidence modified it, with the registry's rating beside it,
// or else the registry's rating, which load holds to the band of the CVSS-B
// baseline.
func SeverityBasis(def *FindingView) string {
	if def.Host == nil || def.Host.CVSS == nil {
		return "the registry's rating for this rule"
	}
	basis := "the CVSS-BE severity on this host"
	if def.CVSS != nil {
		basis += "; the registry rates the rule " + strings.ToUpper(def.CVSS.Severity)
	}
	return basis
}

// TechniqueText renders an ATT&CK technique as its identifier, name and
// tactics. It is shared so every view of a finding cites a technique the same
// way.
func TechniqueText(t finding.Technique) string {
	return fmt.Sprintf("%s %s (%s)", t.ID, t.Name, strings.Join(t.Tactics, ", "))
}

// MitigationText renders an ATT&CK mitigation as its identifier and name.
func MitigationText(m finding.Mitigation) string {
	return m.ID + " " + m.Name
}

// MitigationsText renders mitigations on one line, in the order the
// technique's page lists them.
func MitigationsText(mitigations []finding.Mitigation) string {
	parts := make([]string, 0, len(mitigations))
	for _, m := range mitigations {
		parts = append(parts, MitigationText(m))
	}
	return strings.Join(parts, "; ")
}

// writeReference writes a single reference as ReferenceText renders it.
func writeReference(ew *render.ErrWriter, ref finding.Reference) {
	ew.Printf("    %s\n", ReferenceText(ref))
}

// ReferenceText renders a reference as "Type: Title", appending the URL in
// parentheses when it differs from Title. The registry sets Title to the
// human- or ID-readable form and URL only when a distinct link exists, so the
// two are never printed twice. It is shared so
// every view of a finding cites its references the same way.
func ReferenceText(ref finding.Reference) string {
	if ref.URL != "" && ref.URL != ref.Title {
		return fmt.Sprintf("%s: %s (%s)", ref.Type, ref.Title, ref.URL)
	}
	return fmt.Sprintf("%s: %s", ref.Type, ref.Title)
}

// writeSummary renders the summary block: checks and conditions broken down
// by result, findings by severity. Results that did not occur are left out;
// every severity is printed, so a zero is stated rather than implied.
func writeSummary(ew *render.ErrWriter, v View) {
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

	severities := finding.Severities()
	for i := len(severities) - 1; i >= 0; i-- {
		label := severities[i][:1] + strings.ToLower(severities[i][1:]) + ":"
		ew.Printf("  %-15s  %d\n", label, v.Summary.Findings[severities[i]])
	}
	ew.Printf("Duration:          %s\n", v.Duration)
}

// writeResultCounts renders one count per result that occurred, in
// precedence order.
func writeResultCounts(ew *render.ErrWriter, counts map[finding.Result]int) {
	for _, result := range finding.Results() {
		if count := counts[result]; count > 0 {
			ew.Printf("  %-15s  %d\n", string(result)+":", count)
		}
	}
}
