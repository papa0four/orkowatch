// internal/security/checker/firewall.go

package checker

import (
	"context"

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
