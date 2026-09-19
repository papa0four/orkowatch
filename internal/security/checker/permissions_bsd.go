//go:build freebsd || openbsd || netbsd

// internal/security/checker/permissions_bsd.go

package checker

// platformCriticalPaths lists the paths the BSDs add to the common set.
func platformCriticalPaths() []criticalPath {
	return []criticalPath{
		{"/boot", "Boot directory", permStandardDir},
		{"/root", "Root user directory", permPrivateDir},
		{"/usr/local/etc", "Local configuration", permStandardDir},
	}
}
