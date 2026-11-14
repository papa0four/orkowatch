// internal/security/enrichment/view.go

package enrichment

import "sort"

type (
	// MatchView is the types serialization of a single CVE match for
	// JSON and YAML command output
	MatchView struct {
		CVEID          string  `json:"cve_id" yaml:"cve_id"`
		Source         string  `json:"source" yaml:"source"`
		CVSSBaseScore  float64 `json:"cvss_base_score" yaml:"cvss_base_score"`
		CVSSSeverity   string  `json:"cvss_severity" yaml:"cvss_severity"`
		Description    string  `json:"description,omitempty" yaml:"description,omitempty"`
		KnownExploited bool    `json:"known_exploited" yaml:"known_exploited"`
		PatchAvailable bool    `json:"patch_available" yaml:"patch_available"`
	}

	// EntryView is the types serialization of a single CWE's
	// enrichment result for JSON and YAML command output
	EntryView struct {
		CWEID        string      `json:"cwe_id" yaml:"cwe_id"`
		WeaknessName string      `json:"weakness_name,omitempty" yaml:"weakness_name,omitempty"`
		NoMatches    bool        `json:"no_matches" yaml:"no_matches"`
		Matches      []MatchView `json:"matches,omitempty" yaml:"matches,omitempty"`
	}

	// FailureView is the types serialization of a failed per-CWE
	// enrichment lookup for JSON and YAML command output
	FailureView struct {
		CWEID     string `json:"cwe_id" yaml:"cwe_id"`
		Source    string `json:"source" yaml:"source"`
		Reason    string `json:"reason" yaml:"reason"`
		Retryable bool   `json:"retryable" yaml:"retryable"`
	}
)

// Entries converts enrichment successes into typed serialization
// structs, in the same CWE order as cwes so output order is stable across
// runs.
func Entries(cwes []string, res *Result) []EntryView {
	if res == nil {
		return nil
	}
	out := make([]EntryView, 0, len(cwes))
	for _, cwe := range cwes {
		entry, ok := res.Successes[cwe]
		if !ok {
			continue
		}
		e := EntryView{
			CWEID:        cwe,
			WeaknessName: entry.WeaknessName,
			NoMatches:    entry.Status == StatusNoMatches || len(entry.MatchedCVEs) == 0,
		}
		for _, match := range entry.MatchedCVEs {
			e.Matches = append(e.Matches, MatchView{
				CVEID:          match.CVEID,
				Source:         string(match.Source),
				CVSSBaseScore:  match.CVSSBaseScore,
				CVSSSeverity:   match.CVSSSeverity,
				Description:    match.Description,
				KnownExploited: match.KnownExploited,
				PatchAvailable: match.PatchAvailable,
			})
		}
		out = append(out, e)
	}
	return out
}

// Failures converts enrichment failures into typed serialization
// structs, sorted by CWE ID so serialized output order is stable across
// runs -- Go map iteration order is randomized and would otherwise produce
// nondeterministic diffs in reports
func Failures(res *Result) []FailureView {
	if res == nil || len(res.Failures) == 0 {
		return nil
	}
	out := make([]FailureView, 0, len(res.Failures))
	for _, cwe := range sortedFailureKeys(res.Failures) {
		failure := res.Failures[cwe]
		out = append(out, FailureView{
			CWEID:     cwe,
			Source:    string(failure.Source),
			Reason:    failure.Reason,
			Retryable: failure.Retryable,
		})
	}
	return out
}

// sortedFailureKeys returns the failure map's CWE keys in ascending order,
// giving both the text block and the serialization converters one shared
// definition of failure ordering
func sortedFailureKeys(failures map[string]Failure) []string {
	keys := make([]string, 0, len(failures))
	for cwe := range failures {
		keys = append(keys, cwe)
	}
	sort.Strings(keys)
	return keys
}
