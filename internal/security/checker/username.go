//go:build darwin || freebsd || openbsd || netbsd

// internal/security/checker/username.go

package checker

// isSafeUsername reports whether username can be passed as a command
// argument. The readers that query per-account state through a subprocess
// gate on it so a crafted account name cannot reach the command line.
func isSafeUsername(username string) bool {
	for _, r := range username {
		if (r < 'a' || r > 'z') &&
			(r < 'A' || r > 'Z') &&
			(r < '0' || r > '9') &&
			r != '_' && r != '-' && r != '.' {
			return false
		}
	}
	return len(username) > 0
}
