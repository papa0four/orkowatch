//go:build windows

// internal/report/report_windows.go

package report

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"

	"github.com/papa0four/orkowatch/internal/fspath"
	"github.com/papa0four/orkowatch/internal/winfolder"
)

// refusedFolders are the system locations a report is never written into:
// the OS files and the installed programs.
var refusedFolders = []winfolder.Folder{
	winfolder.Windows,
	winfolder.ProgramFiles,
	winfolder.ProgramFilesX86,
}

// refusedReason names the refused location target lies in, or returns empty
// when it lies in none. The locations are the system folders and every place
// a Startup folder, for every user or for this one, may be, which an attacker
// would use for persistence. None is read from an environment variable. A
// location that cannot be resolved refuses the write: whether target lies in
// it is unknown.
func refusedReason(target string) string {
	bases, err := refusedBases()
	if err != nil {
		return err.Error()
	}
	for _, base := range bases {
		if fspath.Within(target, base) {
			return base
		}
	}
	return ""
}

// refusedBases resolves every refused location.
func refusedBases() ([]string, error) {
	bases, err := winfolder.StartupFolders()
	if err != nil {
		return nil, err
	}
	for _, folder := range refusedFolders {
		base, err := folder.Path()
		if err != nil {
			return nil, err
		}
		bases = append(bases, base)
	}
	return bases, nil
}

// openAndWrite creates target and writes data to it. The name is generated
// per run, so nothing legitimate is ever there already: CREATE_NEW refuses
// whatever is, and OPEN_REPARSE_POINT makes a planted link count as that
// existing entry where the default open would resolve it and create its
// target.
func openAndWrite(target string, data []byte) (err error) {
	path, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return fmt.Errorf("encode path: %w", err)
	}

	handle, err := windows.CreateFile(
		path,
		windows.GENERIC_WRITE,
		0,
		nil,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return fmt.Errorf("create destination: %w", err)
	}
	f := os.NewFile(uintptr(handle), target)
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	if _, werr := f.Write(data); werr != nil {
		return fmt.Errorf("write report: %w", werr)
	}
	return nil
}
