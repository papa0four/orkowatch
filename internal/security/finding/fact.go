// internal/security/finding/fact.go

package finding

import "slices"

type (
	// EvidenceKind names what sort of thing an evidence subject is.
	EvidenceKind string

	// FactName is the name of one observation on an evidence subject.
	FactName string
)

// The evidence kinds checkers record. They are declared here, beside the fact
// names, because the registry declares which kinds a condition's evidence holds
// and the checkers produce them, and the two must agree on the spelling.
const (
	KindFile      EvidenceKind = "file"
	KindAccount   EvidenceKind = "account"
	KindDirective EvidenceKind = "sshd-directive"
	KindManager   EvidenceKind = "firewall-manager"
	KindProfile   EvidenceKind = "firewall-profile"
	KindService   EvidenceKind = "service"
	KindACL       EvidenceKind = "acl-entry"
	KindShare     EvidenceKind = "share"
	KindSetting   EvidenceKind = "setting"
	KindListening EvidenceKind = "listening"
	KindNSSEntry  EvidenceKind = "nss-database"
	KindPAMRule   EvidenceKind = "pam-rule"
)

// The fact names checkers record. The registry's rules read facts by these
// names and the checkers record them, so both take the spelling from here.
const (
	FactDescription      FactName = "description"
	FactMode             FactName = "mode"
	FactExpected         FactName = "expected"
	FactUID              FactName = "uid"
	FactGID              FactName = "gid"
	FactUnresolved       FactName = "unresolved"
	FactReach            FactName = "reach"
	FactLocation         FactName = "location"
	FactShell            FactName = "shell"
	FactSource           FactName = "source"
	FactState            FactName = "state"
	FactValue            FactName = "value"
	FactMatch            FactName = "match"
	FactListing          FactName = "listing"
	FactStatus           FactName = "status"
	FactPrincipal        FactName = "principal"
	FactAccess           FactName = "access"
	FactScope            FactName = "scope"
	FactSID              FactName = "sid"
	FactPasswordRequired FactName = "password_required"
	FactInternetIdentity FactName = "internet_identity"
	FactListening        FactName = "listening"
	FactAddresses        FactName = "addresses"
	FactLine             FactName = "line"
	FactServices         FactName = "services"
	FactVersion          FactName = "version"
	FactGroup            FactName = "group"
	FactGrant            FactName = "grant"
)

// The values of FactListening: how far the listening sockets of a service, or
// of the host, can be reached. A service with a socket on any address other
// than loopback is reachable from the network.
const (
	ListeningNetwork      = "network"
	ListeningLoopbackOnly = "loopback-only"
	ListeningNone         = "none"
	ListeningUndetermined = "undetermined"
)

// The values of FactReach: how far a file whose directory chain mode bits deny
// can be reached. A reachable file records no reach.
const (
	ReachRootOnly     = "root-only"
	ReachUndetermined = "undetermined"
	ReachUnsupported  = "not evaluated on this platform"
)

// The values of FactLocation: the kind of place a scanned path lies in. A path
// in neither records no location.
const (
	LocationTemporary = "temporary"
	LocationHome      = "home"
)

var (
	// evidenceKinds is every kind a checker records.
	evidenceKinds = []EvidenceKind{
		KindFile, KindAccount, KindDirective, KindManager, KindProfile,
		KindService, KindACL, KindShare, KindSetting, KindListening,
		KindNSSEntry, KindPAMRule,
	}

	// factValues is every fact name a checker records, with the values it can
	// take when they are a closed set, and nil when the value is whatever was
	// observed.
	factValues = map[FactName][]string{
		FactDescription:      nil,
		FactMode:             nil,
		FactExpected:         nil,
		FactUID:              nil,
		FactGID:              nil,
		FactUnresolved:       nil,
		FactReach:            {ReachRootOnly, ReachUndetermined, ReachUnsupported},
		FactLocation:         {LocationTemporary, LocationHome},
		FactShell:            nil,
		FactSource:           nil,
		FactState:            nil,
		FactValue:            nil,
		FactMatch:            nil,
		FactListing:          nil,
		FactStatus:           nil,
		FactPrincipal:        nil,
		FactAccess:           nil,
		FactScope:            nil,
		FactSID:              nil,
		FactPasswordRequired: nil,
		FactInternetIdentity: nil,
		FactListening:        {ListeningNetwork, ListeningLoopbackOnly, ListeningNone, ListeningUndetermined},
		FactAddresses:        nil,
		FactLine:             nil,
		FactServices:         nil,
		FactVersion:          nil,
		FactGroup:            nil,
		FactGrant:            nil,
	}
)

// Known reports whether k is a kind a checker records.
func (k EvidenceKind) Known() bool {
	return slices.Contains(evidenceKinds, k)
}

// Known reports whether n is a fact name a checker records.
func (n FactName) Known() bool {
	_, ok := factValues[n]
	return ok
}

// Takes reports whether value is one n can record. A fact that is not
// enumerated takes any value.
func (n FactName) Takes(value string) bool {
	values, ok := factValues[n]
	return ok && (values == nil || slices.Contains(values, value))
}
