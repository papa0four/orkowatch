// internal/security/types/types.go

// Package types defines the vocabulary shared by every checker, renderer, and
// report: the finding and result shapes, the status and severity values that
// appear verbatim in output, and CWE identifier normalization. These are output
// contract values and cannot change once shipped.
package types

import (
	"strings"
	"time"
)

// Display, status, and severity vocabulary shared by every checker and
// renderer. These are output contract values: symbols and status strings
// appear verbatim in text output and reports, and severity strings match
// registry YAML definitions, so none may change once shipped.
const (
	// SymbolOK prefixes detail lines reporting a passing condition.
	SymbolOK = "[+]"
	// SymbolError prefixes detail lines reporting a check execution failure.
	SymbolError = "[-]"
	// SymbolWarning prefixes detail lines reporting a non-critical finding.
	SymbolWarning = "[!]"
	// SymbolInfo prefixes informational detail lines carrying no judgment.
	SymbolInfo = "[*]"
	// SymbolCritical prefixes detail lines reporting a critical finding.
	SymbolCritical = "[X]"

	// StatusCompleted marks a check that ran to completion.
	StatusCompleted = "COMPLETED"
	// StatusWarning marks a check that completed but surfaced conditions
	// requiring attention.
	StatusWarning = "WARNING"
	// StatusError marks a check that failed to execute.
	StatusError = "ERROR"
	// StatusSkipped marks a check excluded from the run by flag selection.
	StatusSkipped = "SKIPPED"
	// StatusChecking marks a check currently executing; results carrying it
	// in final output indicate the check never reached a terminal status.
	StatusChecking = "CHECKING"

	// SeverityLow through SeverityCritical are the canonical severity values
	// in ascending rank order; SeverityLevel defines the ranking.
	SeverityLow = "LOW"
	// SeverityMedium is the second severity rank.
	SeverityMedium = "MEDIUM"
	// SeverityHigh is the third severity rank.
	SeverityHigh = "HIGH"
	// SeverityCritical is the highest severity rank.
	SeverityCritical = "CRITICAL"
)

type (
	// AuditResult represents the result of a security check
	AuditResult struct {
		Name        string        // Name of the check
		Status      string        // Status of the check (using Status constants)
		Description string        // Description of what was checked
		Details     []string      // Detailed findings
		Findings    []Finding     // Structured findings
		StartTime   time.Time     // When the check started
		EndTime     time.Time     // When the check completed
		Duration    time.Duration // How long the check took
	}

	// Finding represents a specific security finding. Metadata carries
	// structured evidence a checker attaches beyond the registry definition;
	// the first writer is the persistence checker tracked as #52, and no
	// renderer projects it until one exists.
	Finding struct {
		Title       string
		Description string
		Severity    string
		Categories  []string
		Impact      string
		Resolution  string
		References  []Reference
		Metadata    map[string]any
	}

	// Reference provides additional information about a finding
	Reference struct {
		Title string `json:"title" yaml:"title"`
		URL   string `json:"url,omitempty" yaml:"url,omitempty"`
		Type  string `json:"type" yaml:"type"` // e.g., "CVE", "CWE", "NIST", "MITRE", etc.
	}

	// ReferenceExtraction separates valid CWEs from malformed CWE attempts
	// and non-CWE references.
	ReferenceExtraction struct {
		CWEs   []string
		Errors []error
	}
)

// severityRank lists the canonical severity values in ascending rank order.
// SeverityLevel, NormalizeSeverity, and SeverityNames all derive from it, so
// the canonical set is enumerated once.
var severityRank = []string{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

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
	default:
		return SymbolInfo, severity
	}
}

// CWEReferences returns the CWE IDs referenced by this
// finding, deduplicated. Order matches first occurrence.
func (f *Finding) CWEReferences() ReferenceExtraction {
	var ext ReferenceExtraction
	if len(f.References) == 0 {
		return ext
	}
	seen := make(map[string]struct{}, len(f.References))
	for _, ref := range f.References {
		if ref.Type == "CWE" {
			id, err := NormalizeCWEID(ref.URL)
			if err != nil {
				id, err = NormalizeCWEID(ref.Title)
			}
			if err != nil {
				ext.Errors = append(ext.Errors, err)
				continue
			}
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			ext.CWEs = append(ext.CWEs, id)
		}
	}
	return ext
}

// AllCWEReferences returns the canonical CWE IDs across all findings
// in this result, deduplicated. Order matches first occurrence.
func (r *AuditResult) AllCWEReferences() ReferenceExtraction {
	var ext ReferenceExtraction
	if len(r.Findings) == 0 {
		return ext
	}
	seen := make(map[string]struct{})
	for i := range r.Findings {
		sub := r.Findings[i].CWEReferences()
		for _, id := range sub.CWEs {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			ext.CWEs = append(ext.CWEs, id)
		}
		ext.Errors = append(ext.Errors, sub.Errors...)
	}
	return ext
}
