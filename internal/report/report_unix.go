//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/report/report_unix.go

package report

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

const (
	reportFileMode = 0600

	// rootID is the superuser's uid and the gid of its group.
	rootID = 0

	// Permission bits the exposure rule reads.
	bitGroupWrite os.FileMode = 0020
	bitOtherWrite os.FileMode = 0002

	// decimalBase and idBitSize describe the numeric identifiers os/user
	// returns as text: base-10, uid_t and gid_t width.
	decimalBase = 10
	idBitSize   = 32
)

// operator is the user behind sudo: the identity an elevated run acts for.
type operator struct {
	uid  uint32
	gid  uint32
	home string
}

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

// canonicalParent resolves the parent chain so the location checks compare
// against the real directory
func canonicalParent(parent string) (string, error) {
	real, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrParentMissing, parent)
	}
	return real, nil
}

func refusedReason(target string) string {
	for _, root := range systemRoots {
		if pathWithin(target, root) {
			return root
		}
	}

	homes := make([]string, 0, maxOperatorHomes)
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		homes = append(homes, home)
	}
	if invoker, ok := invokingOperator(); ok && (len(homes) == 0 || invoker.home != homes[0]) {
		homes = append(homes, invoker.home)
	}
	for _, home := range homes {
		for _, rel := range userPersistence {
			base := filepath.Join(home, rel)
			if pathWithin(target, base) {
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

// withinAllowlist permits an elevated write only under roots the operator clearly owns
func withinAllowlist(target string) (bool, error) {
	for _, root := range allowlistRoots() {
		real, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		if pathWithin(target, real) {
			return true, nil
		}
	}
	return false, nil
}

func allowlistRoots() []string {
	roots := make([]string, 0, maxOperatorHomes)
	if cwd, err := os.Getwd(); err == nil {
		roots = append(roots, cwd)
	}
	if invoker, ok := invokingOperator(); ok {
		roots = append(roots, invoker.home)
	}
	return roots
}

// invokingOperator returns the user behind sudo, so an elevated run can
// still target that user's space rather than only root's. It reports false
// when the run was not started through sudo or the account cannot be
// resolved, which leaves root as the only identity a destination is judged
// against.
func invokingOperator() (operator, bool) {
	name := os.Getenv("SUDO_USER")
	if name == "" {
		return operator{}, false
	}
	u, err := user.Lookup(name)
	if err != nil || u.HomeDir == "" {
		return operator{}, false
	}
	uid, err := strconv.ParseUint(u.Uid, decimalBase, idBitSize)
	if err != nil {
		return operator{}, false
	}
	gid, err := strconv.ParseUint(u.Gid, decimalBase, idBitSize)
	if err != nil {
		return operator{}, false
	}
	return operator{uid: uint32(uid), gid: uint32(gid), home: u.HomeDir}, true
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

// exposure names what lets a user other than root and the invoking operator
// replace entries in dir, or returns the empty string when nothing does.
// Ownership decides first, because a directory's owner can always rename what
// is inside it whatever the mode says. Group and other write are then judged
// by who holds them: root's group and the operator's primary group are
// accepted, and the sticky bit confines other-write to an entry's own owner.
func exposure(dir string) (string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("no ownership information for destination directory")
	}

	invoker, sudo := invokingOperator()
	perm := info.Mode().Perm()

	switch {
	case st.Uid != rootID && (!sudo || st.Uid != invoker.uid):
		return fmt.Sprintf("owned by uid %d, neither root nor the invoking user", st.Uid), nil
	case perm&bitGroupWrite != 0 && st.Gid != rootID && (!sudo || st.Gid != invoker.gid):
		return fmt.Sprintf("group-writable by gid %d, neither root's group nor the invoking user's", st.Gid), nil
	case perm&bitOtherWrite != 0 && info.Mode()&os.ModeSticky == 0:
		return "world-writable without the sticky bit", nil
	default:
		return "", nil
	}
}
