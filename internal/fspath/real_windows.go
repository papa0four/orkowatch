//go:build windows

// internal/fspath/real_windows.go

package fspath

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

// Real returns the long-form path Windows resolves dir to, so a rule about
// where a directory is cannot be evaded by 8.3 short names, links, or trailing
// dots and spaces.
func Real(dir string) (final string, err error) {
	if strings.HasPrefix(dir, `\\?\`) || strings.HasPrefix(dir, `\\.\`) {
		return "", ErrDevicePath
	}

	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return "", fmt.Errorf("encode path: %w", err)
	}

	// Backup semantics are required to obtain a directory handle.
	h, err := windows.CreateFile(
		p,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrMissing, dir)
	}
	defer func() {
		if cerr := windows.CloseHandle(h); cerr != nil && err == nil {
			err = fmt.Errorf("close directory handle: %w", cerr)
		}
	}()

	const finalPathFlags = 0
	buf := make([]uint16, windows.MAX_PATH)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], windows.MAX_PATH, finalPathFlags)
	if err != nil {
		return "", fmt.Errorf("canonicalize path: %w", err)
	}
	if int(n) > len(buf) {
		buf = make([]uint16, n)
		if _, err := windows.GetFinalPathNameByHandle(h, &buf[0], n, finalPathFlags); err != nil {
			return "", fmt.Errorf("canonicalize path: %w", err)
		}
	}

	final = windows.UTF16ToString(buf)
	if rest := strings.TrimPrefix(final, `\\?\UNC\`); rest != final {
		return `\\` + rest, nil
	}
	return strings.TrimPrefix(final, `\\?\`), nil
}
