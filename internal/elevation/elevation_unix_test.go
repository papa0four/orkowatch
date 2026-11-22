//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/elevation/elevation_unix_test.go

package elevation

import (
	"os"
	"os/user"
	"strings"
	"testing"
)

// The operator is the account SUDO_USER names, and there is none when the
// variable is unset or names no account.
func TestInvokingOperator(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("SUDO_USER", me.Username)
	invoker, ok := InvokingOperator()
	if !ok || invoker.Home != me.HomeDir || invoker.uid != uint32(os.Getuid()) || invoker.gid != uint32(os.Getgid()) {
		t.Errorf("SUDO_USER=%s gave %+v, %v, want the current account with home %s", me.Username, invoker, ok, me.HomeDir)
	}

	for _, name := range []string{"", "no-such-account-owatch"} {
		t.Setenv("SUDO_USER", name)
		if invoker, ok := InvokingOperator(); ok {
			t.Errorf("SUDO_USER=%q gave the operator %+v", name, invoker)
		}
	}
}

// A directory is exposed by an owner, a writing group or a writing world that
// is neither root nor the operator, and the sticky bit excuses the last.
func TestExposed(t *testing.T) {
	const (
		alice, staff = 1000, 50
		bob, users   = 1001, 100
	)
	invoker := Operator{uid: alice, gid: staff}
	cases := map[string]struct {
		uid, gid uint32
		mode     os.FileMode
		sudo     bool
		want     string
	}{
		"root's, closed":                        {rootID, rootID, 0o755, false, ""},
		"root's, root's group writes":           {rootID, rootID, 0o775, false, ""},
		"the operator's, closed":                {alice, staff, 0o700, true, ""},
		"the operator's, without sudo":          {alice, staff, 0o700, false, "owned by uid 1000"},
		"another user's":                        {bob, users, 0o700, true, "owned by uid 1001"},
		"the operator's group writes":           {rootID, staff, 0o770, true, ""},
		"that group writes, without sudo":       {rootID, staff, 0o770, false, "group-writable by gid 50"},
		"another group writes":                  {alice, users, 0o770, true, "group-writable by gid 100"},
		"another group, not writing":            {alice, users, 0o750, true, ""},
		"the world writes":                      {rootID, rootID, 0o757, false, "world-writable without the sticky bit"},
		"the world writes under the sticky bit": {rootID, rootID, 0o757 | os.ModeSticky, false, ""},
		"an owner outranks the mode":            {bob, rootID, 0o777, true, "owned by uid 1001"},
	}
	for name, c := range cases {
		got := exposed(c.uid, c.gid, c.mode, invoker, c.sudo)
		if (c.want == "") != (got == "") || !strings.HasPrefix(got, c.want) {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

// A directory the test's own account made is exposed to that account unless
// the account is root or the operator behind sudo.
func TestExposure(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()

	t.Setenv("SUDO_USER", "")
	reason, err := Exposure(dir)
	if err != nil {
		t.Fatal(err)
	}
	if root := os.Getuid() == rootID; root != (reason == "") {
		t.Errorf("without sudo, as uid %d: %q", os.Getuid(), reason)
	}

	t.Setenv("SUDO_USER", me.Username)
	if reason, err := Exposure(dir); err != nil || reason != "" {
		t.Errorf("as the operator's own directory: %q, %v", reason, err)
	}

	if _, err := Exposure(dir + "-absent"); err == nil {
		t.Error("a directory that does not exist was judged")
	}
}
