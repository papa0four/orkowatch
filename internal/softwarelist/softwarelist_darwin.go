//go:build darwin

// internal/softwarelist/softwarelist_darwin.go

package softwarelist

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"slices"
	"strings"
)

// applicationsDataType is the data type system_profiler lists installed
// applications under, and the key its JSON report holds them by.
const applicationsDataType = "SPApplicationsDataType"

// applicationsReport is system_profiler's JSON report of that data type, as a
// Mac wrote it: one object for each application bundle it found, with the
// bundle's name and, for most, its version. The same name appears more than
// once where bundles of one name lie at several paths.
type applicationsReport struct {
	Applications []struct {
		Name    string `json:"_name"`
		Version string `json:"version"`
	} `json:"SPApplicationsDataType"`
}

// getPlatformSoftwareList asks system_profiler for the installed
// applications.
func getPlatformSoftwareList(ctx context.Context) ([]SoftwareEntry, error) {
	output, err := exec.CommandContext(ctx, "system_profiler", applicationsDataType, "-json").Output()
	if err != nil {
		return nil, fmt.Errorf("system_profiler: %w", err)
	}
	return parseApplications(output)
}

// parseApplications reads the report. Bundles of one name and one version
// are one entry, since nothing an entry carries tells them apart; bundles of
// one name and different versions are each kept, because they are different
// software. An application with no version is listed without one.
func parseApplications(output []byte) ([]SoftwareEntry, error) {
	var report applicationsReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("system_profiler: %w", err)
	}

	entries := make([]SoftwareEntry, 0, len(report.Applications))
	for _, app := range report.Applications {
		if app.Name != "" {
			entries = append(entries, SoftwareEntry{Name: app.Name, Version: app.Version})
		}
	}
	slices.SortFunc(entries, func(a, b SoftwareEntry) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.Version, b.Version))
	})
	return slices.Compact(entries), nil
}
