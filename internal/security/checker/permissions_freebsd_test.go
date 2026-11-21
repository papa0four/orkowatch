//go:build freebsd

// internal/security/checker/permissions_freebsd_test.go

package checker

import (
	"os"
	"testing"
)

// FreeBSD judges its own paths at the modes it installs them with: the
// password hashes where FreeBSD keeps them, sudo's file where the package puts
// it, and none of the Linux paths it does not have.
func TestFreeBSDCriticalPaths(t *testing.T) {
	want := map[string]os.FileMode{
		"/etc/passwd":            0o644,
		"/etc/master.passwd":     0o600,
		"/etc/pwd.db":            0o644,
		"/etc/spwd.db":           0o600,
		"/etc/group":             0o644,
		"/usr/local/etc/sudoers": 0o440,
		"/etc/ssh/sshd_config":   0o644,
		"/var/log":               0o755,
		"/home":                  0o755,
		"/root":                  0o750,
		"/boot":                  0o755,
		"/usr/local/etc":         0o755,
	}
	paths := NewPermissionChecker(hostContext, "", nil).paths
	if len(paths) != len(want) {
		t.Errorf("%d critical paths, want %d: %+v", len(paths), len(want), paths)
	}
	for _, cp := range paths {
		mode, ok := want[cp.path]
		switch {
		case !ok:
			t.Errorf("%s is a critical path on FreeBSD", cp.path)
		case cp.expected != mode:
			t.Errorf("%s: expected %s, want %s", cp.path, formatMode(cp.expected), formatMode(mode))
		}
	}
}
