//go:build linux || freebsd

// internal/security/checker/privilege.go

// Who sudo admits, for the platforms where sudo is asked: what sudo answers
// to root, and the groups its packaged rules name for a run that cannot ask.

package checker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
)

const (
	// /etc/group field indices as defined by POSIX. The identifier sits at
	// unixIDField, as it does in /etc/passwd. groupMinFields is the fewest an
	// entry has: FreeBSD's getent ends the entry of a group with no members
	// at its identifier, where glibc's writes an empty member list.
	groupFieldName    = 0
	groupFieldMembers = 3
	groupMinFields    = 3

	// getentProgram reads a database through the name service switch.
	// getentNotFound is the exit status getent(1) gives for a key the
	// database does not hold, which is an answer and not a failed lookup.
	getentProgram  = "getent"
	getentNotFound = 2

	// sudoAdminHeading titles the administrative accounts sudo itself named.
	sudoAdminHeading = "Accounts sudo admits to a shell as root:"
)

// sudoRules are the rules decided by what sudo answers.
var sudoRules = []registry.FindingKey{ruleAdminAccount, ruleSudoUnprompted}

// adminGroups are the groups distributions name in the sudoers they package.
// Membership shows who a host's sudo rules may admit, not that they do: the
// packaged rule is a comment on some distributions and absent on others.
var adminGroups = []string{"sudo", "wheel", "admin"}

type (
	// privilegedGroups is who a set of groups holds, each account and each
	// group identifier by the group's name: an account whose primary group is
	// one of them belongs to it without being listed.
	privilegedGroups struct {
		members map[string]string
		gids    map[uint32]string
	}

	// privilegeSources is where the reader learns who is administrative: who
	// runs the audit, which programs the host has, sudo and the group
	// database.
	privilegeSources struct {
		euid      int
		installed func(program string) bool
		sudo      sudoRun
		groups    func(ctx context.Context) (privilegedGroups, error)
	}
)

// add records the groups in POSIX group-database entries. An entry is
// name:password:gid:comma-separated-members; a line without an identifier is
// skipped rather than treated as a group with no members.
func (g privilegedGroups) add(output []byte) {
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < groupMinFields {
			continue
		}
		group := fields[groupFieldName]
		if gid, ok := parseUnixID(fields[unixIDField]); ok {
			g.gids[gid] = group
		}
		if len(fields) <= groupFieldMembers {
			continue
		}
		for _, member := range strings.Split(fields[groupFieldMembers], ",") {
			if name := strings.TrimSpace(member); name != "" {
				g.members[name] = group
			}
		}
	}
}

// groupOf returns the administrative group account belongs to, by being
// listed or by holding it as its primary group, and "" when it is in none.
func (g privilegedGroups) groupOf(account userAccount) string {
	if group, ok := g.members[account.username]; ok {
		return group
	}
	return g.gids[account.gid]
}

// newPrivilegedGroups returns a set holding no group.
func newPrivilegedGroups() privilegedGroups {
	return privilegedGroups{members: make(map[string]string), gids: make(map[uint32]string)}
}

// readAdminGroups returns who the administrative groups hold. A group that
// does not exist has no members, and getent says so by its exit status; any
// other failure is a lookup that could not be made, which a caller must not
// mistake for a host with no such group.
func readAdminGroups(ctx context.Context) (privilegedGroups, error) {
	groups := newPrivilegedGroups()

	for _, group := range adminGroups {
		entry, err := lookupGroup(ctx, getentProgram, group)
		if err != nil {
			return groups, err
		}
		groups.add(entry)
	}

	return groups, nil
}

// lookupGroup asks getent for one group's entry. A group the database does
// not hold is no entry and no error.
func lookupGroup(ctx context.Context, getent, group string) ([]byte, error) {
	entry, err := exec.CommandContext(ctx, getent, "group", group).Output() // #nosec G204 -- the program is getentProgram outside tests, and a group name is a literal or one the caller has checked
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit) && exit.ExitCode() == getentNotFound:
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("%s group %s: %w", getent, group, execError(err))
	}
	return entry, nil
}

// hostPrivilegeSources are the sources of the host the audit runs on.
func hostPrivilegeSources() privilegeSources {
	return privilegeSources{
		euid:      os.Geteuid(),
		installed: onPath,
		sudo:      runSudo,
		groups:    readAdminGroups,
	}
}

// onPath reports whether program can be run by name.
func onPath(program string) bool {
	_, err := exec.LookPath(program)
	return err == nil
}

// runSudo runs sudo in the C locale, where its messages are the ones the
// reader knows, with no terminal to prompt on.
func runSudo(ctx context.Context, args ...string) (stdout, stderr []byte, status int, err error) {
	cmd := exec.CommandContext(ctx, "sudo", args...) // #nosec G204 -- the arguments are fixed options, a fixed command and an account name checked by isSafeUsername
	cmd.Env = append(os.Environ(), "LC_ALL=C")

	var out, complaint bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &complaint

	err = cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return out.Bytes(), complaint.Bytes(), exit.ExitCode(), nil
	}
	return out.Bytes(), complaint.Bytes(), 0, err
}

// readPrivilege decides who is administrative as far as this run can see.
// As root with sudo installed, sudo is asked of every account. Otherwise the
// rules have no judgment and say why: a caller other than root is not
// answered, and the group names alone do not show what sudo grants.
func (h *hostAccounts) readPrivilege(ctx context.Context, src privilegeSources) {
	const absent = "sudo is not installed"

	sudo := src.installed("sudo")
	switch {
	case sudo && src.euid == rootUID:
		h.askSudo(ctx, src.sudo)
	case sudo:
		h.unjudged = append(h.unjudged, unaskedSudo(ctx, src.groups, h.accounts)...)
	case src.installed("doas"):
		h.unjudged = append(h.unjudged,
			unjudged{rules: []registry.FindingKey{ruleAdminAccount}, result: finding.ResultUnknown,
				reason: absent + " and doas is, and the rules of doas are not read"},
			unjudged{rules: []registry.FindingKey{ruleSudoUnprompted}, result: finding.ResultNotApplicable, reason: absent})
	default:
		h.unjudged = append(h.unjudged, unjudged{rules: sudoRules, result: finding.ResultNotApplicable, reason: absent})
	}
}

// askSudo sets on each account what sudo said of it. An account sudo admits
// only on another account's password is not administrative by that: sudo
// then asks what su asks. What sudo could not read of its own rules leaves
// the rules unknown beside whatever the readable ones admitted.
func (h *hostAccounts) askSudo(ctx context.Context, run sudoRun) {
	var names []string
	for _, account := range h.accounts {
		if isSafeUsername(account.username) {
			names = append(names, account.username)
			continue
		}
		h.warnings = append(h.warnings,
			fmt.Sprintf("account %q has a name that is not passed to sudo; what sudo grants it is not known", account.username))
	}

	view, err := askSudo(ctx, run, names)
	if err != nil {
		h.unjudged = append(h.unjudged, unjudged{rules: sudoRules, result: finding.ResultError, reason: err.Error()})
		return
	}
	if len(view.complaints) > 0 {
		// A rule an account fails outranks one that is unknown, so the
		// complaint is narrated as well: the report says it either way.
		partial := "sudo answered from part of its rules: " + strings.Join(view.complaints, grantDivider)
		h.unjudged = append(h.unjudged, unjudged{rules: sudoRules, result: finding.ResultUnknown, reason: partial})
		h.warnings = append(h.warnings, partial)
	}

	h.adminHeading = sudoAdminHeading
	for i := range h.accounts {
		account := &h.accounts[i]
		answer := view.answers[account.username]

		account.unprompted = answer.unprompted
		if !answer.shell {
			continue
		}
		if answer.borrowed != "" {
			account.borrowed = answer.borrowed
			continue
		}
		account.isAdmin = true
		account.grants = answer.entries
	}
}

// unaskedSudo is the gap of a run that is not root on a host with sudo. The
// regular accounts in an administrative group are recorded as members, which
// is what was seen, and not as accounts sudo admits.
func unaskedSudo(ctx context.Context, read func(context.Context) (privilegedGroups, error), users []userAccount) []unjudged {
	reason := "sudo answers who it admits only to root"

	var members []finding.Evidence
	groups, err := read(ctx)
	if err != nil {
		reason += fmt.Sprintf("; group membership could not be read either: %v", err)
	}
	for _, account := range users {
		if group := groups.groupOf(account); group != "" && !account.isSystem {
			members = append(members, accountEvidence(account, fact(finding.FactGroup, group)))
		}
	}

	return []unjudged{
		{rules: []registry.FindingKey{ruleAdminAccount}, result: finding.ResultError, reason: reason, evidence: members},
		{rules: []registry.FindingKey{ruleSudoUnprompted}, result: finding.ResultError, reason: reason},
	}
}
