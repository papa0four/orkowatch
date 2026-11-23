//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/dataset/store/transient_unix_test.go

package store

import (
	"fmt"
	"syscall"
)

// errPassing is a failure that passes, as the system reports one.
var errPassing = fmt.Errorf("rename: %w", syscall.EBUSY)
