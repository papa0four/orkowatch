//go:build linux

// internal/security/checker/permissions_linux.go

package checker

// platformCriticalPaths lists the paths Linux adds to the common set.
func platformCriticalPaths() []criticalPath {
	return []criticalPath{
		{"/boot", "Boot directory", permStandardDir, false},
		{"/root", "Root user directory", permPrivateDir, false},
		{"/proc", "Process information", permReadOnlyDir, false},
		{"/sys", "System information", permReadOnlyDir, false},
	}
}
