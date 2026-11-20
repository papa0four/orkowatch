//go:build linux || freebsd

// internal/security/checker/credentials.go

// The credential store beside the passwd file, for the platforms whose
// reader opens it, and the range of identifiers that makes an account a
// regular one.

package checker

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// credentialMinFields is the fewest fields a usable line of a credential
// store has: the account name and its password field, which lead a line of
// shadow(5) and of master.passwd(5) alike.
const credentialMinFields = 2

// uidRange is the inclusive range of identifiers assigned to regular
// accounts.
type uidRange struct {
	min uint32
	max uint32
}

func (r uidRange) contains(uid uint32) bool {
	return uid >= r.min && uid <= r.max
}

// readCredentials returns the password field of each account in the
// credential store at path, and whether the store could be opened. A store
// this run may not open is no fields and no error: what was not seen is the
// caller's to report.
func readCredentials(path string) (fields map[string]string, read bool, err error) {
	store, err := os.Open(path) // #nosec G304 -- path is the platform's credential store, a constant
	if err != nil {
		return nil, false, nil
	}
	defer store.Close() //nolint:errcheck // read-only credential store; a close error does not change what was read

	fields = make(map[string]string)
	scanner := bufio.NewScanner(store)
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), ":")
		if len(line) >= credentialMinFields {
			fields[line[passwdFieldUsername]] = line[passwdFieldPassword]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, false, fmt.Errorf("read %s: %w", path, err)
	}
	return fields, true, nil
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
