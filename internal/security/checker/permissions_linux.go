//go:build linux

// internal/security/checker/permissions_linux.go

package checker

import "github.com/papa0four/orkowatch/internal/security/finding"

// platformLocations lists the places Linux adds to the common set: /dev/shm is
// the tmpfs POSIX shared memory objects live in, as shm_overview(7) describes.
func platformLocations() []pathLocation {
	return []pathLocation{{"/dev/shm", finding.LocationTemporary}}
}

// platformCriticalPaths lists the paths Linux adds to the common set.
func platformCriticalPaths() []criticalPath {
	return []criticalPath{
		{"/boot", "Boot directory", permStandardDir},
		{"/root", "Root user directory", permPrivateDir},
		{"/proc", "Process information", permReadOnlyDir},
		{"/sys", "System information", permReadOnlyDir},
	}
}
