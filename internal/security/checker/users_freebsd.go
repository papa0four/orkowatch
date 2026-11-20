//go:build freebsd

// internal/security/checker/users_freebsd.go

package checker

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

const (
	// credentialStore holds the password field of every local account.
	// passwd(5): "The passwd file is generated from the master.passwd file by
	// pwd_mkdb(8), has the class, change, and expire fields removed, and the
	// password field replaced by a ‘*’ character."
	credentialStore = "/etc/master.passwd"

	// credentialsUnread is why the credential rules have no judgment when
	// the store could not be opened.
	credentialsUnread = credentialStore + " is not readable without elevated privileges"

	// pamPolicyDir holds the policy of each service, and suPolicyFile is that
	// of su. su(1): "This group requirement may be changed by modifying the
	// pam_group section of /etc/pam.d/su."
	pamPolicyDir = "/etc/pam.d"
	suPolicyFile = pamPolicyDir + "/" + suService
)

// privilegeRules are the rules on administrative access the FreeBSD reader
// judges: what sudo answers, and what su requires.
var privilegeRules = slices.Concat(sudoRules, suRules())

// platformRules are the rules of platformRuleSet FreeBSD defines. root's
// password is what su asks for, so no rule asks for it to be locked. root and
// toor keep a shell by design, and uucp's is the program its transfers run.
var platformRules = platformRuleSet{ // #nosec G101 -- rule keys and account names, not credentials
	systemShell:     "users.system_account_login_shell",
	nologinPassword: "users.nologin_account_password_set",
	suMember:        "users.su_group_member",
	shellExempt:     []string{"root", "toor", "uucp"},
}

// unusablePrefixes begin a master.passwd password field no one can present.
// passwd(5): "A password of ‘*’ indicates that password authentication is
// disabled for that account", and one "prefixed by ‘*LOCKED*’ means that the
// account is temporarily locked out".
var unusablePrefixes = []string{"*"}

// getUsers reads /etc/passwd and, when readable, /etc/master.passwd, and
// resolves who may become root from what sudo answers and what su requires.
func (u *UnixUserChecker) getUsers(ctx context.Context) ([]userAccount, error) {
	users, err := localAccounts()
	if err != nil {
		return nil, err
	}

	credentials, read, err := readCredentials(credentialStore)
	if err != nil {
		return nil, err
	}
	u.credentialsRead = read

	// A missing pw.conf is the shipped state and leaves the defaults.
	conf, err := os.ReadFile(pwConfFile)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		u.readWarnings = append(u.readWarnings,
			fmt.Sprintf("%s could not be read, so regular accounts are taken to be those pw assigns by default: %v", pwConfFile, err))
	}
	regular := pwUIDRange(conf)
	for i := range users {
		account := &users[i]
		account.isSystem = !regular.contains(account.uid)

		if field, ok := credentials[account.username]; ok {
			account.password = credentialState(field)
		}
	}

	u.readPrivilege(ctx, hostPrivilegeSources(), users)
	u.readSU(ctx, users)
	return users, nil
}

// readSU reads the su service's policy and sets who it admits to root.
func (u *UnixUserChecker) readSU(ctx context.Context, users []userAccount) {
	policy := func(service string) ([]byte, error) {
		return os.ReadFile(filepath.Join(pamPolicyDir, service)) // #nosec G304 -- service is a name readSUGate has refused path separators in
	}
	lookup := func(ctx context.Context, group string) ([]byte, error) {
		return lookupGroup(ctx, getentProgram, group)
	}
	u.applySUGate(ctx, suPolicyFile, readSUGate(policy), lookup, users)
}
