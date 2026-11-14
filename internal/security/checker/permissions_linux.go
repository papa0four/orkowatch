//go:build linux

// internal/security/checker/permissions_linux.go

package checker

// platformCriticalPaths lists the paths Linux adds to the common set.
func platformCriticalPaths() []criticalPath {
	return []criticalPath{
		{"/boot", "Boot directory", permStandardDir},
		{"/root", "Root user directory", permPrivateDir},
		{"/proc", "Process information", permReadOnlyDir},
		{"/sys", "System information", permReadOnlyDir},
	}
}
