//go:build windows

// internal/fspath/open_windows.go

package fspath

import (
	"errors"
	"io/fs"
	"os"

	"golang.org/x/sys/windows"
)

// OpenRegular opens path for reading when it is a regular file, and fails
// with ErrNotRegular when it is anything else. OPEN_REPARSE_POINT opens a
// link itself and not what it leads to, so a file a reader trusts cannot be
// swapped for a pointer to another. What was opened is what is judged: the
// type and attributes are read from the handle, not from the path a second
// time.
func OpenRegular(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	handle, err := windows.CreateFile(
		p,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, classify(path, &fs.PathError{Op: "open", Path: path, Err: err})
	}
	f := os.NewFile(uintptr(handle), path)

	if err := regular(handle); err != nil {
		if errors.Is(err, ErrNotRegular) {
			err = refused(path)
		}
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

// regular reports whether handle is a file on a disk that is neither a
// directory nor a reparse point.
func regular(handle windows.Handle) error {
	kind, err := windows.GetFileType(handle)
	if err != nil {
		return err
	}
	if kind != windows.FILE_TYPE_DISK {
		return ErrNotRegular
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return ErrNotRegular
	}
	return nil
}
