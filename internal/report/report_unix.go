//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/report/report_unix.go

package report

import (
	"os"
	"path/filepath"

	"github.com/papa0four/orkowatch/internal/elevation"
	"github.com/papa0four/orkowatch/internal/fspath"
)

// systemRoots are refused because they sensitive to an attacker
var systemRoots = []string{
	"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64",
	"/boot", "/sys", "/proc", "/dev", "/root",
	"/run", "/var/run", "/var/spool/cron",
	"/System", "/Library/LaunchDaemons", "/Library/LaunchAgents",
}

// userPersistence are home-relative locations that are refused due to their sensitivity
var userPersistence = []string{
	".ssh", ".config/autostart", ".config/systemd/user",
	".bashrc", ".bash_profile", ".profile", ".zshrc",
	"Library/LaunchAgents",
}

func refusedReason(target string) string {
	for _, root := range systemRoots {
		if fspath.Within(target, root) {
			return root
		}
	}

	homes := make([]string, 0, maxOperatorHomes)
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		homes = append(homes, home)
	}
	if invoker, ok := elevation.InvokingOperator(); ok && (len(homes) == 0 || invoker.Home != homes[0]) {
		homes = append(homes, invoker.Home)
	}
	for _, home := range homes {
		for _, rel := range userPersistence {
			base := filepath.Join(home, rel)
			if fspath.Within(target, base) {
				return base
			}
		}
	}
	return ""
}
