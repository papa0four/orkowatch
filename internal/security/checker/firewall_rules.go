//go:build linux || freebsd || windows

// internal/security/checker/firewall_rules.go

package checker

import "strings"

// filterLines returns the trimmed lines of output that keep accepts. Every
// firewall tool's rule listing is reduced this way; only the predicate
// differs between them. It is built for the platforms whose firewall check
// reads a tool's listing.
func filterLines(output []byte, keep func(string) bool) []string {
	lines := make([]string, 0)
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if keep(line) {
			lines = append(lines, line)
		}
	}
	return lines
}
