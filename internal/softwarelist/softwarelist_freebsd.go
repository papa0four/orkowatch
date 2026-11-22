//go:build freebsd

// internal/softwarelist/softwarelist_freebsd.go

package softwarelist

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

const (
	// pkgFormat asks pkg for what pkg-query(8) names: %n the "name of the
	// matched package", %v its version, %o its origin and %q its
	// architecture.
	pkgFormat = "%n\t%v\t%o\t%q"

	fieldSeparator = "\t"
)

// The fields of one line of the answer.
const (
	pkgName = iota
	pkgVersion
	pkgOrigin
	pkgArch
	pkgFields
)

// getPlatformSoftwareList asks pkg for every installed package. On a host
// whose base system is installed as packages, those are among them.
func getPlatformSoftwareList(ctx context.Context) ([]SoftwareEntry, error) {
	output, err := exec.CommandContext(ctx, "pkg", "query", "-a", pkgFormat).Output()
	if err != nil {
		return nil, fmt.Errorf("pkg query: %w", err)
	}
	return parsePkgQuery(string(output))
}

// parsePkgQuery reads the answer. The origin is where the package was built
// from, a category and name in the Ports Collection or the base system, and
// stands as the source of the package.
func parsePkgQuery(output string) ([]SoftwareEntry, error) {
	var entries []SoftwareEntry
	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, fieldSeparator)
		if len(fields) != pkgFields || fields[pkgName] == "" {
			return nil, fmt.Errorf("pkg query: unexpected line %q", line)
		}
		entries = append(entries, SoftwareEntry{
			Name:         fields[pkgName],
			Version:      fields[pkgVersion],
			Manager:      ManagerPkg,
			Architecture: fields[pkgArch],
			Source:       fields[pkgOrigin],
		})
	}
	return entries, nil
}
