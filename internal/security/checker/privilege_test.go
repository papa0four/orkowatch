//go:build linux || freebsd

// internal/security/checker/privilege_test.go

package checker

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
)

// A group the database does not hold is an answer; a lookup that could not
// be made is an error.
func TestLookupGroup(t *testing.T) {
	ctx := context.Background()

	if entry, err := lookupGroup(ctx, getentProgram, "daemon"); err != nil || !strings.HasPrefix(string(entry), "daemon:") {
		t.Errorf("daemon: entry %q, err %v; want its entry", entry, err)
	}
	if entry, err := lookupGroup(ctx, getentProgram, "owatch-no-such-group"); err != nil || entry != nil {
		t.Errorf("a group that does not exist: entry %q, err %v; want neither", entry, err)
	}
	// false exits 1, which is not the status for a key that is not found.
	if _, err := lookupGroup(ctx, "false", "root"); err == nil {
		t.Error("a lookup that exits 1 is taken for a group that does not exist")
	}
	if _, err := lookupGroup(ctx, "owatch-no-such-program", "root"); err == nil {
		t.Error("a missing getent is taken for a group that does not exist")
	}
}

func TestPrivilegedGroupsGroupOf(t *testing.T) {
	groups := privilegedGroups{members: map[string]string{}, gids: map[uint32]string{}}
	groups.add([]byte("sudo:x:27:alice, bob\n"))
	groups.add([]byte("wheel:x:10:\nmalformed line\n"))
	groups.add(nil)

	cases := []struct {
		account userAccount
		want    string
	}{
		{userAccount{username: "alice", gid: 1000}, "sudo"},
		{userAccount{username: "bob", gid: 1001}, "sudo"},
		{userAccount{username: "carol", gid: 10}, "wheel"},
		{userAccount{username: "dave", gid: 1003}, ""},
	}
	for _, tc := range cases {
		if got := groups.groupOf(tc.account); got != tc.want {
			t.Errorf("%s: group %q, want %q", tc.account.username, got, tc.want)
		}
	}
}

// privilegeHost is a host as the reader sees it: who runs the audit, the
// programs installed, what sudo answers and the administrative groups.
type privilegeHost struct {
	euid     int
	programs []string
	sudo     map[string]sudoReply
	groups   string
	groupErr error
}

// judge runs the reader and the judgment over accounts, and returns what was
// recorded with what the report narrates and the requests made of sudo.
func (h privilegeHost) judge(accounts []userAccount) (map[registry.FindingKey]finding.Condition, []string, []string) {
	u := NewUserChecker(hostContext)

	var asked []string
	src := privilegeSources{
		euid:      h.euid,
		installed: func(program string) bool { return slices.Contains(h.programs, program) },
		sudo:      scriptedSudo(h.sudo, &asked),
		groups: func(context.Context) (privilegedGroups, error) {
			groups := newPrivilegedGroups()
			groups.add([]byte(h.groups))
			return groups, h.groupErr
		},
	}

	host := hostAccounts{accounts: slices.Clone(accounts)}
	host.readPrivilege(context.Background(), src)
	r := newReport(u.checkIdentity)
	analyzeUsers(host, r)
	return conditions(r), r.result.Details, asked
}

// The accounts of the cases below: two regular, one of the system.
var privilegeAccounts = []userAccount{
	{username: "alice", uid: 1000, gid: 1000, shell: "/bin/bash"},
	{username: "bob", uid: 1001, gid: 1001, shell: "/bin/bash"},
	{username: "backup", uid: 34, gid: 34, shell: "/usr/sbin/nologin", isSystem: true},
}

const nothingListed = "User x is not allowed to run sudo on host.\n"

func TestReadPrivilegeAsRoot(t *testing.T) {
	limited := "User backup may run the following commands on host:\n    (root) NOPASSWD: /usr/bin/rsync\n"

	cases := []struct {
		name        string
		sudo        map[string]sudoReply
		admin       finding.Result
		adminText   string
		unprompted  finding.Result
		promptText  string
		narration   string
		noNarration string
	}{
		{
			name: "sudo admits a regular account on its own password",
			sudo: map[string]sudoReply{
				"-l -U alice": {stdout: sudoListAdmitted}, "-l -U alice /bin/sh": {stdout: "/bin/sh\n"},
				"-l -U bob": {stdout: nothingListed}, "-l -U backup": {stdout: nothingListed},
			},
			admin: finding.ResultFail, adminText: "alice uid=1000 shell=/bin/bash grant=(ALL : ALL) ALL; (ALL) ALL",
			unprompted: finding.ResultPass,
			narration:  sudoAdminHeading,
		},
		{
			name: "sudo admits nobody",
			sudo: map[string]sudoReply{
				"-l -U alice": {stdout: nothingListed}, "-l -U bob": {stdout: nothingListed}, "-l -U backup": {stdout: nothingListed},
			},
			admin: finding.ResultPass, unprompted: finding.ResultPass,
			noNarration: sudoAdminHeading,
		},
		{
			name: "a later rule undoes the one that admits",
			sudo: map[string]sudoReply{
				"-l -U alice": {stdout: sudoListAdmitted}, "-l -U alice /bin/sh": {status: sudoDenied},
				"-l -U bob": {stdout: nothingListed}, "-l -U backup": {stdout: nothingListed},
			},
			admin: finding.ResultPass, unprompted: finding.ResultPass,
		},
		{
			name: "sudo asks for the target's password",
			sudo: map[string]sudoReply{
				"-l -U alice": {stdout: sudoListTargetpw}, "-l -U alice /bin/sh": {stdout: "/bin/sh\n"},
				"-l -U bob": {stdout: sudoListTargetpw}, "-l -U bob /bin/sh": {stdout: "/bin/sh\n"},
				"-l -U backup": {stdout: sudoListTargetpw}, "-l -U backup /bin/sh": {stdout: "/bin/sh\n"},
			},
			admin: finding.ResultPass, unprompted: finding.ResultPass,
			narration:   "alice (UID: 1000, Shell: /bin/bash) (sudo asks for another account's password: targetpw)",
			noNarration: sudoAdminHeading,
		},
		{
			name: "an entry that asks for no password, on a system account",
			sudo: map[string]sudoReply{
				"-l -U alice": {stdout: nothingListed}, "-l -U bob": {stdout: nothingListed},
				"-l -U backup": {stdout: limited}, "-l -U backup /bin/sh": {status: sudoDenied},
			},
			admin:      finding.ResultPass,
			unprompted: finding.ResultFail, promptText: "backup uid=34 shell=/usr/sbin/nologin grant=(root) NOPASSWD: /usr/bin/rsync",
		},
		{
			name: "sudo could not read all of its rules",
			sudo: map[string]sudoReply{
				"-l -U alice": {stdout: nothingListed, stderr: sudoSyntaxError},
				"-l -U bob":   {stdout: nothingListed, stderr: sudoSyntaxError}, "-l -U backup": {stdout: nothingListed, stderr: sudoSyntaxError},
			},
			admin: finding.ResultUnknown, adminText: "sudo answered from part of its rules: /etc/sudoers.d/20-broken:1:14: syntax error",
			unprompted: finding.ResultUnknown, promptText: "sudo answered from part of its rules: /etc/sudoers.d/20-broken:1:14: syntax error",
		},
		{
			name: "what the readable rules admit is reported beside the complaint",
			sudo: map[string]sudoReply{
				"-l -U alice": {stdout: sudoListAdmitted, stderr: sudoSyntaxError}, "-l -U alice /bin/sh": {stdout: "/bin/sh\n"},
				"-l -U bob": {stdout: nothingListed}, "-l -U backup": {stdout: nothingListed},
			},
			admin: finding.ResultFail, adminText: "alice uid=1000 shell=/bin/bash grant=(ALL : ALL) ALL; (ALL) ALL",
			unprompted: finding.ResultUnknown, promptText: "sudo answered from part of its rules: /etc/sudoers.d/20-broken:1:14: syntax error",
			narration: "sudo answered from part of its rules: /etc/sudoers.d/20-broken:1:14: syntax error",
		},
		{
			name:  "sudo does not answer",
			sudo:  map[string]sudoReply{"-l -U alice": {stderr: "sudo: unable to initialize policy plugin\n", status: 1}},
			admin: finding.ResultError, adminText: "sudo -l -U alice: exit status 1: sudo: unable to initialize policy plugin",
			unprompted: finding.ResultError, promptText: "sudo -l -U alice: exit status 1: sudo: unable to initialize policy plugin",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, details, _ := privilegeHost{euid: rootUID, programs: []string{"sudo"}, sudo: tc.sudo}.judge(privilegeAccounts)

			if result, text := outcome(got[ruleAdminAccount]); result != tc.admin || text != tc.adminText {
				t.Errorf("%s = %s %q, want %s %q", ruleAdminAccount, result, text, tc.admin, tc.adminText)
			}
			if result, text := outcome(got[ruleSudoUnprompted]); result != tc.unprompted || text != tc.promptText {
				t.Errorf("%s = %s %q, want %s %q", ruleSudoUnprompted, result, text, tc.unprompted, tc.promptText)
			}
			narrated := strings.Join(details, "\n")
			if tc.narration != "" && !strings.Contains(narrated, tc.narration) {
				t.Errorf("the report does not say %q:\n%s", tc.narration, narrated)
			}
			if tc.noNarration != "" && strings.Contains(narrated, tc.noNarration) {
				t.Errorf("the report says %q:\n%s", tc.noNarration, narrated)
			}
		})
	}
}

// A run that is not root never asks sudo, which would log the refusal against
// the caller. It records who is in an administrative group as a member.
func TestReadPrivilegeNotRoot(t *testing.T) {
	const reason = "sudo answers who it admits only to root"

	host := privilegeHost{euid: 1000, programs: []string{"sudo", "doas"}, groups: "sudo:x:27:alice,backup\nwheel:x:1001:\n"}
	got, details, asked := host.judge(privilegeAccounts)

	if len(asked) != 0 {
		t.Errorf("sudo was asked %q by a run that is not root", asked)
	}
	admin := got[ruleAdminAccount]
	if admin.Result != finding.ResultError || admin.Reason != reason {
		t.Errorf("%s = %s %q, want error %q", ruleAdminAccount, admin.Result, admin.Reason, reason)
	}
	var members []string
	for _, e := range admin.Evidence {
		members = append(members, e.Subject+" "+factText(e))
	}
	// backup is listed in sudo and is not a regular account.
	want := []string{"alice uid=1000 shell=/bin/bash group=sudo", "bob uid=1001 shell=/bin/bash group=wheel"}
	if !slices.Equal(members, want) {
		t.Errorf("members = %q, want %q", members, want)
	}
	if c := got[ruleSudoUnprompted]; c.Result != finding.ResultError || c.Reason != reason || len(c.Evidence) != 0 {
		t.Errorf("%s = %s %q with %d subjects, want error %q with none", ruleSudoUnprompted, c.Result, c.Reason, len(c.Evidence), reason)
	}
	if narrated := strings.Join(details, "\n"); strings.Contains(narrated, defaultAdminHeading) || strings.Contains(narrated, sudoAdminHeading) {
		t.Errorf("a member of a group is listed as administrative:\n%s", narrated)
	}

	host.groupErr = errors.New("getent group sudo: exit status 1")
	got, _, _ = host.judge(privilegeAccounts)
	wantReason := reason + "; group membership could not be read either: getent group sudo: exit status 1"
	if c := got[ruleAdminAccount]; c.Result != finding.ResultError || c.Reason != wantReason {
		t.Errorf("with the groups unread: %s %q, want error %q", c.Result, c.Reason, wantReason)
	}
}

// With no sudo there is nothing to ask, whoever runs the audit, and a rule
// that does not apply is not concluded as one that passed.
func TestReadPrivilegeWithoutSudo(t *testing.T) {
	const absent = "sudo is not installed"

	for _, euid := range []int{rootUID, 1000} {
		got, _, asked := privilegeHost{euid: euid, groups: "wheel:x:10:alice\n"}.judge(privilegeAccounts)
		for _, key := range sudoRules {
			if c := got[key]; c.Result != finding.ResultNotApplicable || c.Reason != absent {
				t.Errorf("euid %d: %s = %s %q, want notapplicable %q", euid, key, c.Result, c.Reason, absent)
			}
		}
		if len(asked) != 0 {
			t.Errorf("euid %d: sudo was asked %q on a host without it", euid, asked)
		}

		got, _, _ = privilegeHost{euid: euid, programs: []string{"doas"}}.judge(privilegeAccounts)
		if c := got[ruleAdminAccount]; c.Result != finding.ResultUnknown || c.Reason != absent+" and doas is, and the rules of doas are not read" {
			t.Errorf("euid %d, doas: %s = %s %q, want unknown", euid, ruleAdminAccount, c.Result, c.Reason)
		}
		if c := got[ruleSudoUnprompted]; c.Result != finding.ResultNotApplicable || c.Reason != absent {
			t.Errorf("euid %d, doas: %s = %s %q, want notapplicable %q", euid, ruleSudoUnprompted, c.Result, c.Reason, absent)
		}
	}
}

// A name that could be read as an option is not passed to sudo, and the
// report says the account was not asked about.
func TestReadPrivilegeUnsafeName(t *testing.T) {
	accounts := []userAccount{{username: "al ice", uid: 1000, gid: 1000, shell: "/bin/bash"}}
	_, details, asked := privilegeHost{euid: rootUID, programs: []string{"sudo"}, sudo: map[string]sudoReply{}}.judge(accounts)

	if len(asked) != 0 {
		t.Errorf("sudo was asked %q", asked)
	}
	if narrated := strings.Join(details, "\n"); !strings.Contains(narrated, `account "al ice" has a name that is not passed to sudo`) {
		t.Errorf("the report does not say the account was not asked about:\n%s", narrated)
	}
}
