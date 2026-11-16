//go:build freebsd || openbsd || netbsd

// internal/security/checker/permissions_bsd.go

package checker

// platformLocations adds none: where each BSD keeps home directories has not
// been verified on a BSD host here.
func platformLocations() []pathLocation { return nil }

// platformCriticalPaths lists the paths the BSDs add to the common set.
func platformCriticalPaths() []criticalPath {
	return []criticalPath{
		{"/boot", "Boot directory", permStandardDir},
		{"/root", "Root user directory", permPrivateDir},
		{"/usr/local/etc", "Local configuration", permStandardDir},
	}
}
