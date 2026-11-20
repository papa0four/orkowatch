//go:build linux

// internal/security/checker/permissions_linux.go

package checker

import "github.com/papa0four/orkowatch/internal/security/finding"

// platformLocations lists the places Linux adds to the common set: /dev/shm is
// the tmpfs POSIX shared memory objects live in, as shm_overview(7) describes.
func platformLocations() []pathLocation {
	return []pathLocation{{"/dev/shm", finding.LocationTemporary}}
}

// criticalPaths lists the common paths and the ones Linux adds.
func criticalPaths() []criticalPath {
	return append(commonCriticalPaths(),
		criticalPath{"/boot", "Boot directory", permStandardDir},
		criticalPath{"/root", "Root user directory", permPrivateDir},
		criticalPath{"/proc", "Process information", permReadOnlyDir},
		criticalPath{"/sys", "System information", permReadOnlyDir},
	)
}
