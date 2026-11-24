//go:build windows

// internal/report/report_windows.go

package report

import (
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
