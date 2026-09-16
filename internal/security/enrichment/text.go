// internal/security/enrichment/text.go

package enrichment

import (
	"io"

	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/security/types"
)

// Data carries everything the enrichment text block needs to
// render, decoupled from the audit engine's result type so this package
// never has to import the orchestration layer to render its own data
type Data struct {
	Requested  bool
	Err        error
	References types.ReferenceExtraction
	Result     *Result
}

// Block writes the enrichment text rendering: nothing when enrichment was
// not requested, otherwise one of unavailable, no CWE references, or the
// per-CWE entries and failures projected by Entries and Failures, so text
// and structured output describe the same set in the same order. Reference
// parsing errors are appended in every rendered state. The first write
// error, if any, is returned.
func Block(w io.Writer, d Data) error {
	if !d.Requested {
		return nil
	}

	ew := render.NewErrWriter(w)
	ew.Printf("Enrichment:\n")

	switch {
	case d.Err != nil:
		ew.Printf("  Unavailable: %v\n\n", d.Err)
	case len(d.References.CWEs) == 0:
		ew.Printf("  No CWE references found in current findings.\n\n")
	default:
		writeEntries(ew, Entries(d.References.CWEs, d.Result))
		writeFailures(ew, Failures(d.Result))
		ew.Printf("\n")
	}

	referenceErrors(ew, d.References)
	return ew.Err()
}

// writeEntries writes one block per enriched CWE, or a single line when no
// CWE produced data.
func writeEntries(ew *render.ErrWriter, entries []EntryView) {
	if len(entries) == 0 {
		ew.Printf("  No enrichment data returned.\n")
		return
	}

	for _, entry := range entries {
		ew.Printf("  %s", entry.CWEID)
		if entry.WeaknessName != "" {
			ew.Printf(" - %s", entry.WeaknessName)
		}
		ew.Printf("\n")

		if entry.NoMatches {
			ew.Printf("    No CVE matches in queried sources.\n")
			continue
		}
		for _, match := range entry.Matches {
			writeMatch(ew, match)
		}
	}
}

// writeMatch writes one CVE match as its severity line followed by each
// populated detail, indented beneath it.
func writeMatch(ew *render.ErrWriter, match MatchView) {
	symbol, label := types.SeverityFormat(match.CVSSSeverity)
	ew.Printf("    %s %s  %s (%.1f) [%s]\n",
		symbol, label, match.CVEID, match.CVSSBaseScore, match.Source)
	if match.Description != "" {
		ew.Printf("      Description: %s\n", match.Description)
	}
	if match.KnownExploited {
		ew.Printf("      Known Exploited: yes\n")
	}
	if match.PatchAvailable {
		ew.Printf("      Patch Available: yes\n")
	}
}

// writeFailures writes the failed lookups as an indented block, or nothing
// when every lookup succeeded.
func writeFailures(ew *render.ErrWriter, failures []FailureView) {
	if len(failures) == 0 {
		return
	}

	ew.Printf("\n  Failed enrichments:\n")
	for _, failure := range failures {
		ew.Printf("    %s [%s]: %s", failure.CWEID, failure.Source, failure.Reason)
		if failure.Retryable {
			ew.Printf(" (retryable)")
		}
		ew.Printf("\n")
	}
}

// referenceErrors writes reference parsing errors as an indented block,
// or nothing when there are none. It is only reachable through
// Block, which owns the surrounding layout
func referenceErrors(ew *render.ErrWriter, refs types.ReferenceExtraction) {
	if len(refs.Errors) == 0 {
		return
	}
	ew.Printf("  Reference parsing errors:\n")
	for _, err := range refs.Errors {
		ew.Printf("    %v\n", err)
	}
	ew.Printf("\n")
}
