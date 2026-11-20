// internal/security/checker/listening.go

package checker

import (
	"context"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/sockets"
)

type (
	// Listeners is the host's sockets as the audit read them, for the checks
	// that judge how far a service can be reached, or why they were not read.
	Listeners struct {
		View   *sockets.View
		Unread string
	}

	// ListenersFunc returns the host's sockets. The audit reads them once
	// however many checks ask.
	ListenersFunc func(ctx context.Context) Listeners
)

// listeningEvidence records how far the listening sockets keep selects can be
// reached, on a subject named for what they belong to, with their addresses.
// Sockets that were not read leave it undetermined, and the reason is noted.
func listeningEvidence(r *report, subject string, l Listeners, keep func(sockets.Socket) bool) finding.Evidence {
	if l.View == nil {
		r.note(finding.SymbolWarning, "Where %s listens was not determined: %s", subject, l.Unread)
		return evidence(finding.KindListening, subject, fact(finding.FactListening, finding.ListeningUndetermined))
	}

	found := l.View.Listeners(keep)
	value := finding.ListeningNone
	addresses := make([]string, 0, len(found))
	for _, s := range found {
		addresses = append(addresses, s.Protocol+" "+s.Local)
		switch {
		case s.Scope != sockets.ScopeLoopback:
			value = finding.ListeningNetwork
		case value == finding.ListeningNone:
			value = finding.ListeningLoopbackOnly
		}
	}
	return evidence(finding.KindListening, subject,
		fact(finding.FactListening, value), fact(finding.FactAddresses, strings.Join(addresses, ", ")))
}

// undeterminedListening records that where subject listens was not determined,
// and why.
func undeterminedListening(r *report, subject, reason string) finding.Evidence {
	return listeningEvidence(r, subject, Listeners{Unread: reason}, nil)
}
