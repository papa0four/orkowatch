// internal/security/enrichment/enricher.go

package enrichment

import "context"

// Enricher is the interface every enrichment source adapter
// satisfies. Implementations must be safe for concurrent use.
type Enricher interface {
	Enrich(ctx context.Context, req EnrichRequest) (Result, error)
	Source() Source
}

// NewEnricher returns the configured enricher.
func NewEnricher() (Enricher, error) {
	return nil, ErrNoEnricherConfigured
}
