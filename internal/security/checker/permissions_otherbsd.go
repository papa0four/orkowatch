//go:build openbsd || netbsd

// internal/security/checker/permissions_otherbsd.go

// The critical paths of the BSDs that have no finding definitions yet. They
// are what these platforms had before FreeBSD gained its own list and are
// changed only when a host of their platform has been observed.

package checker

// platformLocations adds none: where each of these BSDs keeps home
// directories has not been verified on a host here.
func platformLocations() []pathLocation { return nil }

// criticalPaths lists the common paths and the ones these BSDs add.
func criticalPaths() []criticalPath {
	return append(commonCriticalPaths(),
		criticalPath{"/boot", "Boot directory", permStandardDir},
		criticalPath{"/root", "Root user directory", permPrivateDir},
		criticalPath{"/usr/local/etc", "Local configuration", permStandardDir},
	)
}
