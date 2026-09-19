// internal/security/checker/firewall.go

package checker

import (
	"context"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/types"
)

// FirewallChecker is the firewall configuration check as the audit sees it.
// Each platform supplies NewFirewallChecker under its own build constraint.
type FirewallChecker interface {
	Name() string
	Description() string
	Check(ctx context.Context) types.AuditResult
}

// filterLines returns the trimmed lines of output that keep accepts. Every
// firewall tool's rule listing is reduced this way; only the predicate
// differs between them.
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
