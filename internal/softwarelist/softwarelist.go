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

// The package managers an entry can come from, as an entry names its own, and
// Windows, whose own servicing updates the system its builds name.
// Vulnerability data is published per manager and compared by each manager's
// own version order, so the matching of installed software to CVEs selects
// the data and the comparison by this value.
const (
	ManagerDpkg    = "dpkg"
	ManagerRPM     = "rpm"
	ManagerAPK     = "apk"
	ManagerPacman  = "pacman"
	ManagerPkg     = "pkg"
	ManagerWindows = "windows"
)

// SoftwareEntry is one installed package as its package manager states it.
// Version is the whole version in the manager's own form, with the epoch and
// the release where the manager has them. Source is the package the entry was
// built from, which is what a distribution's security data names, and
// SourceVersion is that package's version where the manager states one apart
// from the entry's own. A field a manager does not have is empty, and an
// entry read from no package manager, an application on Windows or macOS,
// carries a name and a version alone.
type SoftwareEntry struct {
	Name          string `json:"name" yaml:"name"`
	Version       string `json:"version,omitempty" yaml:"version,omitempty"`
	Manager       string `json:"manager,omitempty" yaml:"manager,omitempty"`
	Architecture  string `json:"architecture,omitempty" yaml:"architecture,omitempty"`
	Source        string `json:"source,omitempty" yaml:"source,omitempty"`
	SourceVersion string `json:"source_version,omitempty" yaml:"source_version,omitempty"`
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
// structured slice. ctx bounds the platform package-manager invocations.
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
