//go:build windows

// internal/fspath/create_windows.go

package fspath

import (
	"io/fs"
	"os"

	"golang.org/x/sys/windows"
)

// CreateNew creates path and opens it for writing, and fails with fs.ErrExist
// when anything is already there. CREATE_NEW refuses whatever is, and
// OPEN_REPARSE_POINT makes a planted link count as that existing entry, where
// the default open would resolve it and create its target. The mode is not
// used: a file on Windows takes its access from the directory it is made in.
func CreateNew(path string, _ os.FileMode) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	handle, err := windows.CreateFile(
		p,
		windows.GENERIC_WRITE,
		0,
		nil,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}
