//go:build darwin

// internal/softwarelist/softwarelist_darwin.go

package softwarelist

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// getPlatformSoftwareList asks system_profiler for the installed
// applications.
func getPlatformSoftwareList(ctx context.Context) ([]SoftwareEntry, error) {
	output, err := exec.CommandContext(ctx, "system_profiler", "SPApplicationsDataType", "-json").Output()
	if err != nil {
		return nil, fmt.Errorf("insufficient permissions to list software packages; try rerunning with sudo")
	}
	return parseDarwinJSON(output), nil
}

// parseDarwinJSON parses system_profiler SPApplicationsDataType -json output
// into a slice of SoftwareEntry. This is a best-effort line-based fallback;
// a full JSON parser will replace this when the Darwin runner lands.
func parseDarwinJSON(output []byte) []SoftwareEntry {
	var entries []SoftwareEntry
	seen := make(map[string]bool)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "\"_name\"") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				name := strings.Trim(strings.TrimSpace(parts[1]), `",`)
				if name != "" && !seen[name] {
					seen[name] = true
					entries = append(entries, SoftwareEntry{Name: name})
				}
			}
		}
	}
	return entries
}
