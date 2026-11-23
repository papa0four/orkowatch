//go:build freebsd

// internal/security/checker/users_freebsd.go

package checker

import (
	"context"
	"os"
	"path/filepath"
	"slices"

	"github.com/papa0four/orkowatch/internal/account"
)

const (
	// credentialStore holds the password field of every local account.
	// passwd(5): "The passwd file is generated from the master.passwd file by
	// pwd_mkdb(8), has the class, change, and expire fields removed, and the
	// password field replaced by a ‘*’ character."
	credentialStore = "/etc/master.passwd"

	// uidRangeFile configures the range pw(8) assigns to regular accounts.
	uidRangeFile = pwConfFile

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

// regularUIDRange returns the range pw assigns to regular accounts, from the
// content of pw.conf.
func regularUIDRange(conf []byte) uidRange {
	return pwUIDRange(conf)
}

// readHostAccounts reads /etc/passwd and, when readable, /etc/master.passwd,
// and resolves who may become root from what sudo answers and what su
// requires.
func readHostAccounts(ctx context.Context) (hostAccounts, error) {
	host, err := readStoredAccounts(ctx)
	if err != nil {
		return host, err
	}

	policy := func(service string) ([]byte, error) {
		return os.ReadFile(filepath.Join(pamPolicyDir, service)) // #nosec G304 -- service is a name readSUGate has refused path separators in
	}
	lookup := func(ctx context.Context, group string) ([]byte, error) {
		return lookupGroup(ctx, account.GetentProgram, group)
	}
	host.applySUGate(ctx, suPolicyFile, readSUGate(policy), lookup)
	return host, nil
}
