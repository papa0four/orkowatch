//go:build linux || freebsd || openbsd || netbsd

// internal/account/lookup_nss.go

package account

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

const (
	// GetentProgram reads a database through the name service switch, which
	// holds the entries of every source the host is configured for.
	GetentProgram = "getent"

	// GetentNotFound is the exit status getent(1) gives for a key the
	// database does not hold, which is an answer and not a failed lookup.
	GetentNotFound = 2
)

// Local returns the accounts the local passwd file declares.
func Local() ([]Account, error) {
	data, err := os.ReadFile(PasswdFile)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", PasswdFile, err)
	}
	return ParseAll(data), nil
}

// lookup finds the account match picks: in the local file first, which needs
// no other process, and then through the name service by key, which reaches a
// directory service. The name service's answer is held to match as well, so
// a reply for another account is not taken for this one.
func lookup(ctx context.Context, key string, match func(Account) bool) (Account, error) {
	if accounts, err := Local(); err == nil {
		for _, a := range accounts {
			if match(a) {
				return a, nil
			}
		}
	}

	out, err := exec.CommandContext(ctx, GetentProgram, "passwd", key).Output() // #nosec G204 -- the program is fixed and the key is an identifier or a name holding no separator
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit) && exit.ExitCode() == GetentNotFound:
		return Account{}, ErrNotFound
	case err != nil:
		return Account{}, fmt.Errorf("%s passwd %s: %w", GetentProgram, key, err)
	}
	for _, a := range ParseAll(out) {
		if match(a) {
			return a, nil
		}
	}
	return Account{}, ErrNotFound
}
