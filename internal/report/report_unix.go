//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/report/report_unix.go

package report

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/papa0four/orkowatch/internal/elevation"
	"github.com/papa0four/orkowatch/internal/fspath"
)

const (
	reportFileMode = 0600

	// rootID is the superuser's uid and the gid of its group.
	rootID = 0
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

// isElevated reports root, where a write can land anywhere and the tool becomes
// a privileged write primitive.
func isElevated() (bool, error) {
	return os.Geteuid() == rootID, nil
}

// openAndWrite creates target and writes data to it. The name is generated
// per run, so nothing legitimate is ever there already: exclusive creation
// refuses whatever is, including a link or FIFO planted to redirect a
// privileged write, where an open that tolerated an existing entry would
// follow or truncate it.
func openAndWrite(target string, data []byte) (err error) {
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, reportFileMode) // #nosec G304 -- target validated through the guard pipeline and created exclusively
	if err != nil {
		return fmt.Errorf("create destination: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	if _, werr := f.Write(data); werr != nil {
		return fmt.Errorf("write report: %w", werr)
	}
	return nil
}
