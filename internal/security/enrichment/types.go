// internal/security/enrichment/types.go

package enrichment

import "time"

type (
	// Source identifies which enrichment adapter contributed a field
	// value. The adapters are tracked as #89 through #93; none is configured
	// yet, so every value below is written by nothing in this tree.
	Source string

	// Status reports the terminal state of an enrichment attempt for a single
	// CWE. Only StatusNoMatches is produced today; the rest are set by the
	// adapters in #89 through #93.
	Status string
)

const (
	// Enrichment adapter source identifiers, one per adapter in #89 through #93.
	SourceNVD   Source = "NVD"
	SourceKEV   Source = "CISA-KEV"
	SourceEPSS  Source = "EPSS"
	SourceGHSA  Source = "GHSA"
	SourceMITRE Source = "MITRE-CWE"

	// Enrichment status values.
	StatusEnriched         Status = "ENRICHED"
	StatusFailed           Status = "FAILED"
	StatusNoMatches        Status = "NO_MATCHES"
	StatusNoSourcesQueried Status = "NO_SOURCES_QUERIED"
)

type (
	// CWEEnrichment is per-CWE enrichment data with per-field source
	// attribution. The attribution and description fields are filled by the
	// adapters in #89 through #93 and are not yet projected by any view.
	CWEEnrichment struct {
		CWEID  string
		Status Status

		WeaknessName       string
		WeaknessNameSource Source

		WeaknessDescription       string
		WeaknessDescriptionSource Source

		MatchedCVEs       []CVEMatch
		MatchedCVEsSource Source

		LastQueried time.Time
	}

	// CVEMatch is a single CVE returned by an enrichment source as
	// associated with a CWE.
	CVEMatch struct {
		CVEID         string
		Source        Source
		CVSSBaseScore float64
		CVSSSeverity  string
		CVSSVector    string

		Published    time.Time
		LastModified time.Time

		KnownExploited         bool
		ExploitPredictionScore float64
		PatchAvailable         bool

		Description string
		References  []string
	}

	// Failure records why enrichment for a specific CWE failed. Err holds the
	// adapter's underlying error for the adapters in #89 through #93; the
	// projections render Reason.
	Failure struct {
		CWEID     string
		Source    Source
		Reason    string
		Err       error
		Retryable bool
	}

	// Result is the aggregate output of an enrichment run. AdapterErrors,
	// SourcesQueried and Duration are populated by the adapters in #89 through
	// #93.
	Result struct {
		Successes      map[string]CWEEnrichment
		Failures       map[string]Failure
		AdapterErrors  []error
		SourcesQueried []Source
		Duration       time.Duration
	}

	// EnrichRequest is the input to Enricher.Enrich. BypassCache, Sources and
	// MinSeverity are honored by the adapters in #89 through #93.
	EnrichRequest struct {
		CWEs        []string
		BypassCache bool
		Sources     []Source
		MinSeverity string
	}
)
