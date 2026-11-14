//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/softwarelist/softwarelist_unix.go

package softwarelist

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// getPlatformSoftwareList returns installed software as a structured slice
// by querying the platform package manager. Linux tries dpkg-query then rpm;
// Darwin uses system_profiler; FreeBSD uses pkg info. OpenBSD and NetBSD are
// wired but not implemented: both use pkg_info, and the module reports the gap
// rather than enumerating with an unverified parser.
func getPlatformSoftwareList(ctx context.Context) ([]SoftwareEntry, error) {
	switch runtime.GOOS {
	case "linux":
		if output, err := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Package}\t${Version}\n").Output(); err == nil {
			return parseTabDelimited(string(output)), nil
		}
		if output, err := exec.CommandContext(ctx, "rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}\n").Output(); err == nil {
			return parseTabDelimited(string(output)), nil
		}
		return nil, fmt.Errorf("no supported package manager found; try rerunning with sudo")

	case "darwin":
		output, err := exec.CommandContext(ctx, "system_profiler", "SPApplicationsDataType", "-json").Output()
		if err != nil {
			return nil, fmt.Errorf("insufficient permissions to list software packages; try rerunning with sudo")
		}
		return parseDarwinJSON(output), nil

	case "freebsd":
		output, err := exec.CommandContext(ctx, "pkg", "info", "-a", "--raw-format", "json").Output()
		if err != nil {
			return nil, fmt.Errorf("insufficient permissions to list software packages; try rerunning with sudo")
		}
		return parseFreeBSDJSON(output), nil

	case "openbsd", "netbsd":
		return nil, fmt.Errorf("software enumeration is not yet implemented for %s", runtime.GOOS)

	default:
		return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// parseTabDelimited parses tab-delimited name\tversion output from dpkg-query
// and rpm into a slice of SoftwareEntry.
func parseTabDelimited(output string) []SoftwareEntry {
	var entries []SoftwareEntry
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 2)
		if len(fields) == 0 || fields[0] == "" {
			continue
		}
		entry := SoftwareEntry{Name: fields[0]}
		if len(fields) == 2 {
			entry.Version = fields[1]
		}
		entries = append(entries, entry)
	}
	return entries
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

// parseFreeBSDJSON parses pkg info -a --raw-format json output into a slice
// of SoftwareEntry. This is a best-effort line-based fallback; a full JSON
// parser will replace this when the FreeBSD runner lands.
func parseFreeBSDJSON(output []byte) []SoftwareEntry {
	var entries []SoftwareEntry
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "\"name\"") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				name := strings.Trim(strings.TrimSpace(parts[1]), `",`)
				if name != "" {
					entries = append(entries, SoftwareEntry{Name: name})
				}
			}
		}
	}
	return entries
}
