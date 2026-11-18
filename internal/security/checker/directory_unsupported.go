//go:build darwin || freebsd || openbsd || netbsd

// internal/security/checker/directory_unsupported.go

package checker

import "context"

// checkDirectoryClients records nothing: the directory client rules are
// defined for Linux alone.
func (u *UnixUserChecker) checkDirectoryClients(context.Context, *report) {}
