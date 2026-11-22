//go:build freebsd

// internal/security/checker/users_freebsd_test.go

package checker

import (
	"context"
	"slices"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
)

// hostContext is the platform the tests shared with Linux judge accounts
// on: the rules a platform's reader names are the ones that platform defines.
var hostContext = registry.OSContext{Platform: registry.PlatformUnix, Families: []registry.Distro{registry.DistroFreeBSD}}

// freebsdAccounts are accounts as FreeBSD ships and pw creates them, with the
// password state master.passwd gives each.
var freebsdAccounts = []userAccount{
	{username: "root", uid: 0, gid: 0, shell: "/bin/sh", isSystem: true, password: passwordEmpty},
	{username: "toor", uid: 0, gid: 0, shell: "", isSystem: true, password: passwordLocked},
	{username: "daemon", uid: 1, gid: 1, shell: "/usr/sbin/nologin", isSystem: true, password: passwordLocked},
	{username: "uucp", uid: 66, gid: 66, shell: "/usr/local/libexec/uucp/uucico", isSystem: true, password: passwordLocked},
	{username: "www", uid: 80, gid: 80, shell: "/bin/sh", isSystem: true, password: passwordLocked},
	{username: "nobody", uid: 65534, gid: 65534, shell: "/usr/sbin/nologin", isSystem: true, password: passwordLocked},
	{username: "a_w", uid: 1001, gid: 1001, shell: "/bin/sh", password: passwordSet},
	{username: "a_p", uid: 1002, gid: 1002, shell: "/bin/sh", password: passwordLocked},
	{username: "a_none", uid: 1003, gid: 1003, shell: "/bin/sh", password: passwordEmpty},
	{username: "a_ftp", uid: 1004, gid: 1004, shell: "/usr/sbin/nologin", password: passwordSet},
}

// judgeFreeBSD applies a su policy to the accounts and judges them as the
// users check does on a host without sudo.
func judgeFreeBSD(gate suGate, credentialsRead bool) map[registry.FindingKey]finding.Condition {
	u := NewUserChecker(hostContext)

	host := hostAccounts{accounts: slices.Clone(freebsdAccounts)}
	if !credentialsRead {
		host.credentialsUnread = credentialStore + " is not readable without elevated privileges"
		for i := range host.accounts {
			host.accounts[i].password = passwordUnknown
		}
	}
	src := privilegeSources{elevated: true, installed: func(string) bool { return false }}
	host.readPrivilege(context.Background(), src)
	lookup := func(context.Context, string) ([]byte, error) { return []byte("wheel:*:0:root,a_w\n"), nil }
	host.applySUGate(context.Background(), suPolicyFile, gate, lookup)

	r := newReport(u.checkIdentity)
	analyzeUsers(host, r)
	return conditions(r)
}

// subjects returns the accounts a condition names, in order.
func subjects(c finding.Condition) []string {
	var names []string
	for _, e := range c.Evidence {
		names = append(names, e.Subject)
	}
	slices.Sort(names)
	return names
}

// Each rule FreeBSD defines fails for the accounts in its state and no
// others, and the rule that asks for root's password to be locked is not
// reported at all.
func TestFreeBSDAccountsAsRoot(t *testing.T) {
	got := judgeFreeBSD(suGate{group: "wheel"}, true)

	fails := map[registry.FindingKey][]string{
		"users.empty_password_hash":          {"a_none", "root"},
		"users.no_password_login_shell":      {"a_none", "root"},
		"users.uid_zero_non_root":            {"toor"},
		"users.su_group_member":              {"a_w"},
		"users.login_shell_present":          {"a_none", "a_p", "a_w"},
		"users.system_account_login_shell":   {"www"},
		"users.nologin_account_password_set": {"a_ftp"},
	}
	for key, want := range fails {
		c := got[key]
		if c.Result != finding.ResultFail || !slices.Equal(subjects(c), want) {
			t.Errorf("%s: %s for %q, want fail for %q", key, c.Result, subjects(c), want)
		}
	}

	if c := got["users.su_group_member"]; len(c.Evidence) == 1 {
		group := ""
		for _, f := range c.Evidence[0].Facts {
			if f.Name == finding.FactGroup {
				group = f.Value
			}
		}
		if group != "wheel" {
			t.Errorf("the member is recorded with the group %q, want wheel", group)
		}
	}
	if c := got[ruleSUOpen]; c.Result != finding.ResultPass {
		t.Errorf("%s: %s, want pass where a group is required", ruleSUOpen, c.Result)
	}
	for _, key := range sudoRules {
		if c := got[key]; c.Result != finding.ResultNotApplicable || c.Reason != "sudo is not installed" {
			t.Errorf("%s: %s %q, want notapplicable without sudo", key, c.Result, c.Reason)
		}
	}
	if c, ok := got["users.root_account_unlocked"]; ok {
		t.Errorf("users.root_account_unlocked is reported: %s", c.Result)
	}
	if _, ok := got[""]; ok {
		t.Error("a rule with no key is reported")
	}
}

// A policy with no group rule fails the host and leaves the membership rule
// without a subject; one the reader does not decide leaves both unknown.
func TestFreeBSDSUPolicies(t *testing.T) {
	got := judgeFreeBSD(suGate{open: true}, true)
	if c := got[ruleSUOpen]; c.Result != finding.ResultFail || !slices.Equal(subjects(c), []string{suPolicyFile}) {
		t.Errorf("%s: %s for %q, want fail for %s", ruleSUOpen, c.Result, subjects(c), suPolicyFile)
	}
	if c := got["users.su_group_member"]; c.Result != finding.ResultNotApplicable {
		t.Errorf("users.su_group_member: %s %q, want notapplicable", c.Result, c.Reason)
	}

	const reason = "line 9 of the policy of su gives pam_group the option deny"
	got = judgeFreeBSD(suGate{undecided: reason}, true)
	for _, key := range suRules() {
		if c := got[key]; c.Result != finding.ResultUnknown || c.Reason != reason {
			t.Errorf("%s: %s %q, want unknown %q", key, c.Result, c.Reason, reason)
		}
	}
}

// A run that cannot open master.passwd judges no credential, and says which
// file it could not read.
func TestFreeBSDAccountsWithoutTheStore(t *testing.T) {
	got := judgeFreeBSD(suGate{group: "wheel"}, false)

	const reason = "/etc/master.passwd is not readable without elevated privileges"
	for _, key := range []registry.FindingKey{"users.empty_password_hash", "users.no_password_login_shell", "users.nologin_account_password_set"} {
		if c := got[key]; c.Result != finding.ResultError || c.Reason != reason {
			t.Errorf("%s: %s %q, want error %q", key, c.Result, c.Reason, reason)
		}
	}
	if c := got["users.su_group_member"]; c.Result != finding.ResultFail || !slices.Equal(subjects(c), []string{"a_w"}) {
		t.Errorf("users.su_group_member: %s for %q, want fail for a_w", c.Result, subjects(c))
	}
}

// master.passwd marks a field no one can present with a leading asterisk,
// alone or as the prefix pw lock writes.
func TestFreeBSDPasswordFields(t *testing.T) {
	cases := map[string]passwordState{
		"":                   passwordEmpty,
		"*":                  passwordLocked,
		"*LOCKED*$6$salt$h":  passwordLocked,
		"*LOCKED*":           passwordLocked,
		"$6$salt$hash":       passwordSet,
		"$2b$04$saltandhash": passwordSet,
	}
	for field, want := range cases {
		if got := credentialState(field); got != want {
			t.Errorf("%q: %d, want %d", field, got, want)
		}
	}
}
