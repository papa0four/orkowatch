// internal/security/enrichment/errors.go

package enrichment

import "errors"

var (
	// ErrNoEnricherConfigured indicates that no enrichment source adapter has been registered.
	ErrNoEnricherConfigured = errors.New("no enrichment source configured")

	// ErrEmptyRequest indicates an EnrichRequest contained no CWE identifiers to
	// enrich. No current producer: designated consumers are the enrichment
	// source adapters (NVD, CISA KEV, EPSS, GHSA), which share this sentinel so
	// an empty request reports identically regardless of source.
	ErrEmptyRequest = errors.New("enrichment request contains no CWE identifiers")

	// ErrMissingAPIKey indicates an adapter requiring an API key could not find
	// the credential. No current producer: designated consumers are the
	// enrichment source adapters that need a key, which share this sentinel so
	// a missing credential reports identically regardless of source.
	ErrMissingAPIKey = errors.New("required API key not found in environment")
)
