// internal/account/doc.go

// Package account reads Unix account records as the system holds them: an
// account's name, identifiers, home, and shell, and the numeric identifiers
// the passwd and group databases write. A program built without cgo, as owatch
// releases are, has a Go lookup that reads /etc/passwd alone and falls back to
// the environment, so an account from a directory service is either not found
// or found where HOME says. This package reads the local file and then asks
// the name service, which holds every account the host resolves, and reads no
// environment variable.
//
// The identifiers are read on every platform, since a test reads a Unix
// host's files on any of them; the records and the lookups are Unix only.
package account
