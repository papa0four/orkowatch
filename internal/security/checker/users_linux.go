//go:build linux

// internal/security/checker/users_linux.go

package checker

import (
	"bufio"
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
	// loginDefsFile configures the range useradd assigns to regular accounts.
	// The defaults are the ones login.defs(5) documents for a missing key.
	loginDefsFile = "/etc/login.defs"
	defaultUIDMin = 1000
	defaultUIDMax = 60000

	// loginDefsFields is the key and value a login.defs setting consists of.
	loginDefsFields = 2

	// shadowMinFields is the fewest fields a usable /etc/shadow line has:
	// the account name and its password field.
	shadowMinFields = 2

	// /etc/group field indices and minimum field count as defined by POSIX.
	// The identifier sits at unixIDField, as it does in /etc/passwd.
	groupFieldName    = 0
	groupFieldMembers = 3
	groupFieldCount   = 4

	// getentProgram reads a database through the name service switch.
	// getentNotFound is the exit status getent(1) gives for a key the
	// database does not hold, which is an answer and not a failed lookup.
	getentProgram  = "getent"
	getentNotFound = 2

	// sudoAdminHeading titles the administrative accounts sudo itself named.
	sudoAdminHeading = "Accounts sudo admits to a shell as root:"
)

// privilegeRules are the rules on administrative access the Linux reader
// judges.
var privilegeRules = []registry.FindingKey{ruleAdminAccount, ruleSudoUnprompted}

// adminGroups are the groups distributions name in the sudoers they package.
// Membership shows who a host's sudo rules may admit, not that they do: the
// packaged rule is a comment on some distributions and absent on others.
var adminGroups = []string{"sudo", "wheel", "admin"}

type (
	// uidRange is the inclusive range of identifiers assigned to regular
	// accounts.
	uidRange struct {
		min uint32
		max uint32
	}

	// privilegedGroups is who the administrative groups hold, each account
	// and each group identifier by the group's name: an account whose primary
	// group is one of them belongs to it without being listed.
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

// regularUIDRange returns the range login.defs assigns to regular accounts.
// An account above UID_MAX is as much a system account as one below UID_MIN:
// nobody and the identifiers services allocate for themselves sit there. A
// missing file or key leaves the documented default in place.
func regularUIDRange() uidRange {
	regular := uidRange{min: defaultUIDMin, max: defaultUIDMax}

	data, err := os.ReadFile(loginDefsFile)
	if err != nil {
		return regular
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < loginDefsFields {
			continue
		}
		value, ok := parseUnixID(fields[1])
		if !ok {
			continue
		}
		switch fields[0] {
		case "UID_MIN":
			regular.min = value
		case "UID_MAX":
			regular.max = value
		}
	}
	return regular
}

func (r uidRange) contains(uid uint32) bool {
	return uid >= r.min && uid <= r.max
}

// shadowPasswordState classifies the password field of a shadow entry. A
// field beginning with ! or * was locked by passwd -l or never assigned; an
// empty field admits a login with no credential at all.
func shadowPasswordState(field string) passwordState {
	switch {
	case field == "":
		return passwordEmpty
	case strings.HasPrefix(field, "!"), strings.HasPrefix(field, "*"):
		return passwordLocked
	default:
		return passwordSet
	}
}

// add records the groups in POSIX group-database entries. An entry is
// name:password:gid:comma-separated-members; a line with fewer fields is
// skipped rather than treated as a group with no members.
func (g privilegedGroups) add(output []byte) {
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < groupFieldCount {
			continue
		}
		group := fields[groupFieldName]
		if gid, ok := parseUnixID(fields[unixIDField]); ok {
			g.gids[gid] = group
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

// readPrivilegedGroups returns the administrative groups the host has. A
// group that does not exist has no members, and getent says so by its exit
// status; any other failure is a lookup that could not be made, which a
// caller must not mistake for a host with no such group.
func readPrivilegedGroups(ctx context.Context) (privilegedGroups, error) {
	groups := privilegedGroups{
		members: make(map[string]string),
		gids:    make(map[uint32]string),
	}

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
	entry, err := exec.CommandContext(ctx, getent, "group", group).Output() // #nosec G204 -- the program is getentProgram outside tests and the group names are literals
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
		groups:    readPrivilegedGroups,
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

// getUsers reads /etc/passwd and, when readable, /etc/shadow, and resolves
// who is administrative from what the host lets this run see.
func (u *UnixUserChecker) getUsers(ctx context.Context) ([]userAccount, error) {
	users, err := localAccounts()
	if err != nil {
		return nil, err
	}

	shadowEntries := make(map[string]string)
	if shadow, err := os.Open("/etc/shadow"); err == nil {
		u.shadowReadable = true
		defer shadow.Close() //nolint:errcheck // read-only shadow file; close error does not affect scan results
		scanner := bufio.NewScanner(shadow)
		for scanner.Scan() {
			fields := strings.Split(scanner.Text(), ":")
			if len(fields) >= shadowMinFields {
				shadowEntries[fields[passwdFieldUsername]] = fields[passwdFieldPassword]
			}
		}

		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading /etc/shadow: %w", err)
		}
	}

	regular := regularUIDRange()
	for i := range users {
		account := &users[i]
		account.isSystem = !regular.contains(account.uid)

		if entry, ok := shadowEntries[account.username]; ok {
			account.password = shadowPasswordState(entry)
		}
	}

	u.readPrivilege(ctx, hostPrivilegeSources(), users)
	return users, nil
}

// readPrivilege decides who is administrative as far as this run can see.
// As root with sudo installed, sudo is asked of every account. Otherwise the
// rules have no judgment and say why: a caller other than root is not
// answered, and the group names alone do not show what sudo grants.
func (u *UnixUserChecker) readPrivilege(ctx context.Context, src privilegeSources, users []userAccount) {
	const absent = "sudo is not installed"

	switch {
	case src.installed("sudo") && src.euid == rootUID:
		u.askSudo(ctx, src.sudo, users)
	case src.installed("sudo"):
		u.unjudged = unaskedSudo(ctx, src.groups, users)
	case src.installed("doas"):
		u.unjudged = []unjudged{
			{rules: []registry.FindingKey{ruleAdminAccount}, result: finding.ResultUnknown,
				reason: absent + " and doas is, and the rules of doas are not read"},
			{rules: []registry.FindingKey{ruleSudoUnprompted}, result: finding.ResultNotApplicable, reason: absent},
		}
	default:
		u.unjudged = []unjudged{{rules: privilegeRules, result: finding.ResultNotApplicable, reason: absent}}
	}
}

// askSudo sets on each account what sudo said of it. An account sudo admits
// only on another account's password is not administrative by that: sudo
// then asks what su asks. What sudo could not read of its own rules leaves
// the rules unknown beside whatever the readable ones admitted.
func (u *UnixUserChecker) askSudo(ctx context.Context, run sudoRun, users []userAccount) {
	var names []string
	for _, account := range users {
		if isSafeUsername(account.username) {
			names = append(names, account.username)
			continue
		}
		u.readWarnings = append(u.readWarnings,
			fmt.Sprintf("account %q has a name that is not passed to sudo; what sudo grants it is not known", account.username))
	}

	view, err := askSudo(ctx, run, names)
	if err != nil {
		u.unjudged = []unjudged{{rules: privilegeRules, result: finding.ResultError, reason: err.Error()}}
		return
	}
	if len(view.complaints) > 0 {
		// A rule an account fails outranks one that is unknown, so the
		// complaint is narrated as well: the report says it either way.
		partial := "sudo answered from part of its rules: " + strings.Join(view.complaints, grantDivider)
		u.unjudged = []unjudged{{rules: privilegeRules, result: finding.ResultUnknown, reason: partial}}
		u.readWarnings = append(u.readWarnings, partial)
	}

	u.adminHeading = sudoAdminHeading
	for i := range users {
		account := &users[i]
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
