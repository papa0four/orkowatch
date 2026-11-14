// internal/security/enrichment/doc.go

// Package enrichment annotates findings with vulnerability intelligence looked
// up by CWE identifier: weakness names, associated CVEs, CVSS scores, known
// exploitation status, and exploit prediction scores. It defines the adapter
// interface, the aggregate result shape, and the serializable and text
// projections of an enrichment run. No source adapter is configured, so
// NewEnricher returns ErrNoEnricherConfigured.
package enrichment
