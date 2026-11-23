//go:build windows

// internal/dataset/store/transient_windows_test.go

package store

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// errPassing is a failure that passes, as the system reports one.
var errPassing = fmt.Errorf("rename: %w", windows.ERROR_SHARING_VIOLATION)
