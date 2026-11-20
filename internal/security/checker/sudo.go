// internal/security/checker/sudo.go

package checker

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

// sudoShell is the command sudo is asked about: an account that may run it
// as root holds the host. POSIX names sh, and Linux and FreeBSD keep it at
// this path.
const sudoShell = "/bin/sh"

// sudoDenied is the exit status of sudo -l with a command the account may
// not run.
const sudoDenied = 1

// What sudo -l prints in the C locale, as far as the reader depends on it.
const (
	sudoDefaultsHeader  = "Matching Defaults entries for "
	sudoEntriesHeader   = " may run the following commands on "
	sudoUnpromptedTag   = "NOPASSWD:"
	sudoPromptedTag     = "PASSWD:"
	sudoUnpromptedFlag  = "!authenticate"
	sudoDefaultsDivider = ", "
)

// sudoBorrowedFlags are the settings under which sudo asks for a password
// that is not the invoking account's: the target's, or root's.
var sudoBorrowedFlags = []string{"targetpw", "rootpw", "runaspw"}

type (
	// sudoRun runs sudo with args in the C locale and returns what it wrote
	// to each stream and its exit status. The error is for a sudo that could
	// not be run at all.
	sudoRun func(ctx context.Context, args ...string) (stdout, stderr []byte, status int, err error)

	// sudoAnswer is what sudo said of one account.
	sudoAnswer struct {
		// shell is set when the account may run sudoShell as root.
		shell bool
		// entries are the rules sudo lists for the account, as it prints
		// them.
		entries []string
		// unprompted are the entries that ask for no password.
		unprompted []string
		// borrowed names the settings in force under which sudo asks for
		// another account's password.
		borrowed string
	}

	// sudoView is what sudo said of every account asked. complaints are what
	// it wrote to standard error while answering: sudo answers from the rules
	// it could read and says which it could not.
	sudoView struct {
		answers    map[string]sudoAnswer
		complaints []string
	}
)

// askSudo asks sudo what each account may do. sudo applies its own grammar,
// its includes, its host and group matching and the last rule that matches,
// and answers for rules served from a directory as for those in files, so
// its answer is taken in place of a second reading of sudoers. Only root is
// answered without a password, and a refused request is logged against the
// caller, so the caller must be root.
func askSudo(ctx context.Context, run sudoRun, accounts []string) (sudoView, error) {
	view := sudoView{answers: make(map[string]sudoAnswer, len(accounts))}

	for _, account := range accounts {
		listing, complaint, status, err := run(ctx, "-l", "-U", account)
		if err != nil {
			return view, fmt.Errorf("sudo could not be run: %w", err)
		}
		if status != 0 {
			return view, fmt.Errorf("sudo -l -U %s: exit status %d: %s", account, status, firstLine(complaint))
		}
		view.complain(complaint)

		answer := parseSudoList(listing)
		if len(answer.entries) > 0 {
			// The list prints every rule that names the account, including
			// one a later rule undoes. Asking about a command has sudo
			// apply them.
			_, complaint, status, err := run(ctx, "-l", "-U", account, sudoShell)
			switch {
			case err != nil:
				return view, fmt.Errorf("sudo could not be run: %w", err)
			case status == 0:
				answer.shell = true
			case status != sudoDenied:
				return view, fmt.Errorf("sudo -l -U %s %s: exit status %d: %s", account, sudoShell, status, firstLine(complaint))
			}
			view.complain(complaint)
		}
		view.answers[account] = answer
	}

	return view, nil
}

// complain records the first line of what sudo wrote to standard error, once.
func (v *sudoView) complain(stderr []byte) {
	if line := firstLine(stderr); line != "" && !slices.Contains(v.complaints, line) {
		v.complaints = append(v.complaints, line)
	}
}

// parseSudoList reads the output of sudo -l -U for one account: the Defaults
// in force for it, and the entries it may run. An account sudo does not admit
// has no entries.
func parseSudoList(listing []byte) sudoAnswer {
	const (
		elsewhere = iota
		inDefaults
		inEntries
	)

	var (
		answer   sudoAnswer
		defaults []string
		section  = elsewhere
	)
	for _, line := range strings.Split(string(listing), "\n") {
		text := strings.TrimSpace(line)
		indented := text != "" && text != strings.TrimRight(line, " \t\r")

		switch {
		case !indented && strings.HasPrefix(text, sudoDefaultsHeader):
			section = inDefaults
		case !indented && strings.Contains(text, sudoEntriesHeader):
			section = inEntries
		case !indented:
			section = elsewhere
		case section == inDefaults:
			defaults = append(defaults, strings.Split(text, sudoDefaultsDivider)...)
		case section == inEntries:
			answer.entries = append(answer.entries, text)
		}
	}

	var borrowed []string
	for _, flag := range sudoBorrowedFlags {
		if slices.Contains(defaults, flag) {
			borrowed = append(borrowed, flag)
		}
	}
	answer.borrowed = strings.Join(borrowed, sudoDefaultsDivider)

	authenticates := !slices.Contains(defaults, sudoUnpromptedFlag)
	for _, entry := range answer.entries {
		if sudoEntryUnprompted(entry, authenticates) {
			answer.unprompted = append(answer.unprompted, entry)
		}
	}
	return answer
}

// sudoEntryUnprompted reports whether an entry lets a command run with no
// password: it carries the NOPASSWD tag, or the account's Defaults turn
// authentication off and the entry does not turn it back on with PASSWD.
func sudoEntryUnprompted(entry string, authenticates bool) bool {
	if strings.Contains(entry, sudoUnpromptedTag) {
		return true
	}
	return !authenticates && !strings.Contains(entry, sudoPromptedTag)
}

// firstLine returns the first line of output that is not blank.
func firstLine(output []byte) string {
	for _, line := range strings.Split(string(output), "\n") {
		if text := strings.TrimSpace(line); text != "" {
			return text
		}
	}
	return ""
}
