//go:build linux || freebsd

// internal/security/checker/credentials_test.go

package checker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
)

// The account name and password field lead a line of shadow and of
// master.passwd alike, and a store that cannot be opened is reported as not
// read, with no error.
func TestReadCredentials(t *testing.T) {
	store := filepath.Join(t.TempDir(), "store")
	lines := "root::0:0::0:0:Charlie &:/root:/bin/sh\n" +
		"toor:*:0:0::0:0:Bourne-again Superuser:/root:\n" +
		"alice:$6$salt$hash:19000:0:99999:7:::\n" +
		"# a comment\n" +
		"\n"
	if err := os.WriteFile(store, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}

	fields, read, err := readCredentials(store)
	if err != nil || !read {
		t.Fatalf("read %v, err %v", read, err)
	}
	want := map[string]string{"root": "", "toor": "*", "alice": "$6$salt$hash"}
	if len(fields) != len(want) {
		t.Errorf("fields %q, want %q", fields, want)
	}
	for name, field := range want {
		if got, ok := fields[name]; !ok || got != field {
			t.Errorf("%s: %q, %v; want %q", name, got, ok, field)
		}
	}

	if fields, read, err := readCredentials(filepath.Join(t.TempDir(), "absent")); fields != nil || read || err != nil {
		t.Errorf("a store that cannot be opened: %q, %v, %v", fields, read, err)
	}
}

// An empty field is no password, a field the platform marks unusable is
// locked, and anything else is a password.
func TestCredentialState(t *testing.T) {
	cases := map[string]passwordState{
		"":             passwordEmpty,
		"*":            passwordLocked,
		"*LOCKED*$6$x": passwordLocked,
		"$6$salt$hash": passwordSet,
	}
	for field, want := range cases {
		if got := credentialState(field); got != want {
			t.Errorf("%q: %d, want %d", field, got, want)
		}
	}
}

// pw.conf moves the range pw assigns to regular accounts; without the file,
// or without its keywords, the documented defaults stand.
func TestPWUIDRange(t *testing.T) {
	// As pw useradd -D -u 2000,3000 wrote it on FreeBSD 15.1.
	written := "#\n# pw.conf - user/group configuration defaults\n#\n" +
		"defaultpasswd = \"no\"\n" +
		"# Range of valid default user ids\n" +
		"minuid = 2000\nmaxuid = 3000\n" +
		"# Range of valid default group ids\n" +
		"mingid = 1000\nmaxgid = 32000\n"

	cases := []struct {
		name string
		conf string
		want uidRange
	}{
		{"no file", "", uidRange{min: 1000, max: 32000}},
		{"as pw writes it", written, uidRange{min: 2000, max: 3000}},
		{"one keyword", "maxuid = 60000\n", uidRange{min: 1000, max: 60000}},
		{"not a number", "minuid = many\n# minuid = 5\n", uidRange{min: 1000, max: 32000}},
	}
	for _, tc := range cases {
		if got := pwUIDRange([]byte(tc.conf)); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}

	if regular := pwUIDRange(nil); regular.contains(65534) || !regular.contains(1001) || regular.contains(999) {
		t.Error("nobody, the first account pw creates and a system account are not told apart")
	}
}

// FreeBSD's getent ends the entry of a group with no members at its
// identifier. The group is still one an account can hold as its primary.
func TestGroupEntryWithoutMembers(t *testing.T) {
	groups := privilegedGroups{members: map[string]string{}, gids: map[uint32]string{}}
	groups.add([]byte("sugroup:*:1001\n"))

	if got := groups.groupOf(userAccount{username: "carol", gid: 1001}); got != "sugroup" {
		t.Errorf("an account whose primary group has no members listed: %q, want sugroup", got)
	}
	if got := groups.groupOf(userAccount{username: "dave", gid: 1002}); got != "" {
		t.Errorf("an account outside the group: %q", got)
	}
}

// errFailedLookup is a group lookup that could not be made.
var errFailedLookup = errors.New("getent group wheel: exit status 1")

// suHost applies a su policy to accounts and returns them with what the
// reader left without a judgment and what it observed of the host.
func suHost(t *testing.T, gate suGate, entry string, lookupErr error, accounts []userAccount) (*UnixUserChecker, []userAccount) {
	t.Helper()
	u := NewUserChecker(registry.OSContext{Platform: registry.PlatformUnix, Families: []registry.Distro{registry.DistroFreeBSD}})
	lookup := func(context.Context, string) ([]byte, error) {
		if entry == "" {
			return nil, lookupErr
		}
		return []byte(entry), lookupErr
	}
	users := append([]userAccount(nil), accounts...)
	u.applySUGate(context.Background(), "/etc/pam.d/su", gate, lookup, users)
	return u, users
}

// An account is admitted by su where the group the policy names lists it or
// is its primary group, as su admitted them on FreeBSD 15.1.
func TestApplySUGate(t *testing.T) {
	accounts := []userAccount{
		{username: "root", uid: 0, gid: 0, isSystem: true},
		{username: "a_w", uid: 1001, gid: 1001},
		{username: "a_p", uid: 1002, gid: 1002},
		{username: "a_g", uid: 1003, gid: 0},
	}

	u, users := suHost(t, suGate{group: "wheel"}, "wheel:*:0:root,a_w\n", nil, accounts)
	want := map[string]string{"root": "wheel", "a_w": "wheel", "a_p": "", "a_g": "wheel"}
	for _, account := range users {
		if account.suGroup != want[account.username] {
			t.Errorf("%s: group %q, want %q", account.username, account.suGroup, want[account.username])
		}
	}
	if len(u.unjudged) != 0 || len(u.hostwide) != 0 {
		t.Errorf("a decided policy left %+v and observed %+v", u.unjudged, u.hostwide)
	}

	u, users = suHost(t, suGate{open: true}, "", nil, accounts)
	if len(u.hostwide) != 1 || u.hostwide[0].rule != ruleSUOpen || u.hostwide[0].evidence.Subject != "/etc/pam.d/su" {
		t.Errorf("a policy with no group rule observed %+v", u.hostwide)
	}
	for _, account := range users {
		if account.suGroup != "" {
			t.Errorf("%s is given the group %q by a policy that names none", account.username, account.suGroup)
		}
	}

	for name, tc := range map[string]struct {
		gate   suGate
		entry  string
		result finding.Result
		reason string
	}{
		"undecided":       {suGate{undecided: "line 9 gives pam_group the option deny"}, "", finding.ResultUnknown, "line 9 gives pam_group the option deny"},
		"no such group":   {suGate{group: "sugroup"}, "", finding.ResultUnknown, "the group sugroup that /etc/pam.d/su names does not exist"},
		"an option name":  {suGate{group: "-s"}, "wheel:*:0:root\n", finding.ResultUnknown, `the group "-s" that /etc/pam.d/su names is not a name passed to getent`},
		"an unsafe name":  {suGate{group: "a b"}, "wheel:*:0:root\n", finding.ResultUnknown, `the group "a b" that /etc/pam.d/su names is not a name passed to getent`},
		"a failed lookup": {suGate{group: "wheel"}, "", finding.ResultError, "getent group wheel: exit status 1"},
	} {
		var lookupErr error
		if tc.result == finding.ResultError {
			lookupErr = errFailedLookup
		}
		u, _ := suHost(t, tc.gate, tc.entry, lookupErr, accounts)
		if len(u.unjudged) != 1 || u.unjudged[0].result != tc.result || u.unjudged[0].reason != tc.reason {
			t.Errorf("%s: %+v, want %s %q", name, u.unjudged, tc.result, tc.reason)
		}
	}
}
