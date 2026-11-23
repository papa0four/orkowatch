//go:build darwin

// internal/account/lookup_darwin.go

package account

import (
	"context"
	"errors"
	"os/user"
	"strconv"
)

// lookup finds the account match picks through Directory Services. On macOS
// Go asks the system library even without cgo, and that library holds local
// and directory accounts alike, so the local file is not read first. key is
// an identifier when it is numeric and a name otherwise.
func lookup(ctx context.Context, key string, match func(Account) bool) (Account, error) {
	if err := ctx.Err(); err != nil {
		return Account{}, err
	}
	var u *user.User
	var err error
	if _, numeric := ParseID(key); numeric {
		u, err = user.LookupId(key)
	} else {
		u, err = user.Lookup(key)
	}
	var unknownID user.UnknownUserIdError
	var unknownName user.UnknownUserError
	switch {
	case errors.As(err, &unknownID), errors.As(err, &unknownName):
		return Account{}, ErrNotFound
	case err != nil:
		return Account{}, err
	}

	uid, ok := ParseID(u.Uid)
	if !ok {
		return Account{}, errors.New("account " + key + " has the identifier " + strconv.Quote(u.Uid))
	}
	gid, ok := ParseID(u.Gid)
	if !ok {
		return Account{}, errors.New("account " + key + " has the group " + strconv.Quote(u.Gid))
	}
	a := Account{Name: u.Username, UID: uid, GID: gid, Home: u.HomeDir}
	if !match(a) {
		return Account{}, ErrNotFound
	}
	return a, nil
}
