// internal/softwarelist/softwarelist.go

// Package softwarelist enumerates installed software packages on the host.
// It provides both a structured list for programmatic consumption and a
// text renderer for human-readable text output.
package softwarelist

import (
	"context"
	"fmt"
	"io"
)

// SoftwareEntry represents a single installed software package with its
// display name and version string as reported by the host platform.
// Name and Version are discrete fields to support downstream CPE lookups
// and enrichment adapter queries against vulnerability databases.
type SoftwareEntry struct {
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
}

// SoftwareView is the serializable projection of a software inventory. This
// is the single structured shape for the software section across every
// command.
type SoftwareView struct {
	Count    int             `json:"count" yaml:"count"`
	Packages []SoftwareEntry `json:"packages" yaml:"packages"`
}

// View returns entries' serializable projection.
func View(entries []SoftwareEntry) SoftwareView {
	return SoftwareView{
		Count:    len(entries),
		Packages: entries,
	}
}

// GetInstalledSoftwareList returns the installed software packages as a
// structured slice. Each entry carries a discrete name and version field
// suitable for enrichment lookups and structured report output. ctx bounds
// the platform package-manager invocations.
func GetInstalledSoftwareList(ctx context.Context) ([]SoftwareEntry, error) {
	entries, err := getPlatformSoftwareList(ctx)
	if err != nil {
		return nil, fmt.Errorf("software enumeration failed: %w", err)
	}
	return entries, nil
}

// WriteText writes v to w as fixed-width name and version columns, one
// package per line, with a leading column header row. This is the single
// software-section text renderer, called by both the standalone software
// command and all.
func WriteText(w io.Writer, v SoftwareView) error {
	if _, err := fmt.Fprintf(w, "%-60s %s\n", "Name", "Version"); err != nil {
		return fmt.Errorf("softwarelist: write failed: %w", err)
	}
	for _, e := range v.Packages {
		if _, err := fmt.Fprintf(w, "%-60s %s\n", e.Name, e.Version); err != nil {
			return fmt.Errorf("software: write failed: %w", err)
		}
	}
	return nil
}
