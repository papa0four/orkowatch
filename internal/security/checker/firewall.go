// internal/security/checker/firewall.go

package checker

import (
	"context"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// FirewallChecker is the firewall configuration check as the audit sees it.
// Each platform supplies NewFirewallChecker under its own build constraint.
type FirewallChecker interface {
	Name() string
	Description() string
	Check(ctx context.Context) finding.AuditResult
}

// hostSubject names the host as a whole in the evidence of where it listens.
const hostSubject = "host"

// hostListening records where the host listens: every TCP socket listening and
// every UDP socket bound, on any address. A firewall's absence matters as far
// as these can be reached.
func hostListening(r *report, listeners Listeners) finding.Evidence {
	return listeningEvidence(r, hostSubject, listeners, nil)
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
