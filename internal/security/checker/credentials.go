//go:build linux || freebsd

// internal/security/checker/credentials.go

// The reader the Linux and FreeBSD platforms share: the local accounts, the
// credential store beside the passwd file, and the range of identifiers that
// makes an account a regular one.

package checker

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// The fields that lead a line of a credential store, shadow(5) and
// master.passwd(5) alike: the account name and its password field.
// credentialMinFields is the fewest a usable line has.
const (
	credentialFieldName = iota
	credentialFieldPassword
	credentialMinFields
)

// uidRange is the inclusive range of identifiers assigned to regular
// accounts.
type uidRange struct {
	min uint32
	max uint32
}

func (r uidRange) contains(uid uint32) bool {
	return uid >= r.min && uid <= r.max
}

// readStoredAccounts reads the local accounts with the password state the
// platform's credential store gives each, marks those outside the range the
// platform assigns to regular accounts, and resolves who is administrative
// from what sudo answers. A store this run lacks the privilege to open leaves
// the credential rules without a judgment, and so does one that cannot be
// read for any other reason, which is not a matter of privilege and is said
// as what it is.
func readStoredAccounts(ctx context.Context) (hostAccounts, error) {
	accounts, err := localAccounts()
	if err != nil {
		return hostAccounts{}, err
	}
	credentials, err := readCredentials(credentialStore)
	host := hostAccounts{accounts: accounts, credentialsUnread: unreadReason(credentialStore, err)}

	// A missing file leaves the documented defaults, and is the shipped
	// state where the platform writes the file only when a default changes.
	conf, err := os.ReadFile(uidRangeFile)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		host.warnings = append(host.warnings, fmt.Sprintf(
			"%s could not be read, so regular accounts are taken to be those in its default range: %v", uidRangeFile, err))
	}
	regular := regularUIDRange(conf)

	for i := range host.accounts {
		account := &host.accounts[i]
		account.isSystem = !regular.contains(account.uid)

		if field, ok := credentials[account.username]; ok {
			account.password = credentialState(field)
		}
	}

	host.readPrivilege(ctx, hostPrivilegeSources())
	return host, nil
}

// unreadReason says why the credential rules have no judgment when reading
// the store at path gave err, and is empty when it gave none. Only a refusal
// for want of privilege is one a run with more privilege would not meet.
func unreadReason(path string, err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, fs.ErrPermission):
		return path + " is not readable without elevated privileges"
	default:
		return fmt.Sprintf("the credential store could not be read: %v", err)
	}
}

// readCredentials returns the password field of each account in the
// credential store at path. The error says why the store was not read, and
// is fs.ErrPermission for one this run lacks the privilege to open.
func readCredentials(path string) (map[string]string, error) {
	store, err := os.Open(path) // #nosec G304 -- path is the platform's credential store, a constant
	if err != nil {
		return nil, err
	}
	defer store.Close() //nolint:errcheck // read-only credential store; a close error does not change what was read

	fields := make(map[string]string)
	scanner := bufio.NewScanner(store)
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), ":")
		if len(line) >= credentialMinFields {
			fields[line[credentialFieldName]] = line[credentialFieldPassword]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return fields, nil
}

// credentialState classifies the password field of a credential store entry.
// An empty field admits a login with no credential at all, and one beginning
// with a prefix the platform lists in unusablePrefixes is not a password
// anyone can present.
func credentialState(field string) passwordState {
	if field == "" {
		return passwordEmpty
	}
	for _, prefix := range unusablePrefixes {
		if strings.HasPrefix(field, prefix) {
			return passwordLocked
		}
	}
	return passwordSet
}
