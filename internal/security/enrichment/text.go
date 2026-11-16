// internal/security/enrichment/text.go

package enrichment

import (
	"io"

	"github.com/papa0four/orkowatch/internal/render"
	"github.com/papa0four/orkowatch/internal/security/finding"
)

// Data is everything the enrichment text block renders from: the projections
// a saved report carries, so a live run and a saved report show the same
// block, and this package never has to import the orchestration layer to
// render its own data. Err is the reason enrichment was unavailable, empty
// when it was not.
type Data struct {
	Requested bool
	Err       string
	CWEs      []string
	Entries   []EntryView
	Failures  []FailureView
}

// Block writes the enrichment text rendering: nothing when enrichment was
// not requested, otherwise one of unavailable, no CWE references, or the
// per-CWE entries and failures, so text and structured output describe the
// same set in the same order. The first write error, if any, is returned.
func Block(w io.Writer, d Data) error {
	if !d.Requested {
		return nil
	}

	ew := render.NewErrWriter(w)
	ew.Printf("Enrichment:\n")

	switch {
	case d.Err != "":
		ew.Printf("  Unavailable: %s\n\n", d.Err)
	case len(d.CWEs) == 0:
		ew.Printf("  No CWE references found in current findings.\n\n")
	default:
		writeEntries(ew, d.Entries)
		writeFailures(ew, d.Failures)
		ew.Printf("\n")
	}

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
	symbol, label := finding.SeverityFormat(match.CVSSSeverity)
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
