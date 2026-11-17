//go:build windows

// internal/winfolder/winfolder_windows.go

package winfolder

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/windows"
)

// Folder is a Windows known folder.
type Folder struct {
	name string
	id   *windows.KNOWNFOLDERID
}

// The known folders owatch uses, named as the known-folder API names them.
// Each was confirmed to resolve to the same place in a process started with
// SystemRoot, windir, ProgramFiles, ProgramData, ALLUSERSPROFILE, APPDATA or
// USERPROFILE pointing elsewhere.
var (
	Windows         = Folder{"Windows", windows.FOLDERID_Windows}
	System          = Folder{"System", windows.FOLDERID_System}
	ProgramFiles    = Folder{"ProgramFiles", windows.FOLDERID_ProgramFiles}
	ProgramFilesX86 = Folder{"ProgramFilesX86", windows.FOLDERID_ProgramFilesX86}
	ProgramData     = Folder{"ProgramData", windows.FOLDERID_ProgramData}
	UserProfiles    = Folder{"UserProfiles", windows.FOLDERID_UserProfiles}
)

// The Startup folders are not in that set: the known-folder API expands
// environment variables in them when a process first asks, so a process
// started with ProgramData elsewhere is told CommonStartup is elsewhere, and
// one started with USERPROFILE elsewhere is told the same of Startup.
var (
	startup       = Folder{"Startup", windows.FOLDERID_Startup}
	commonStartup = Folder{"CommonStartup", windows.FOLDERID_CommonStartup}
)

// startupUnderBase is where both Startup folders lie by default: under the
// ProgramData folder for every user, and under the account's roaming
// application data for one.
var startupUnderBase = []string{"Microsoft", "Windows", "Start Menu", "Programs", "Startup"}

// Name is the folder's known-folder name, for messages.
func (f Folder) Name() string { return f.name }

// Path returns where Windows has put the folder on this host, joined with
// elem when given. The folder is not required to exist: an account whose
// profile has no Startup folder still has a place one would be, and a caller
// looking a file up there finds nothing rather than failing. A folder Windows
// cannot resolve is an error naming it.
func (f Folder) Path(elem ...string) (string, error) {
	path, err := windows.KnownFolderPath(f.id, windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		return "", fmt.Errorf("the %s folder could not be resolved: %w", f.name, err)
	}
	return filepath.Join(append([]string{path}, elem...)...), nil
}

// Profile returns the profile folder of the account running this process, as
// Windows records it for the account. USERPROFILE, which os.UserHomeDir reads,
// is whatever the process was started with.
func Profile() (string, error) {
	profile, err := windows.GetCurrentProcessToken().GetUserProfileDirectory()
	if err != nil {
		return "", fmt.Errorf("the account's profile folder could not be resolved: %w", err)
	}
	return profile, nil
}

// StartupFolders returns every place the Startup folders, for every user and
// for the account running this process, may be: their default locations under
// the ProgramData folder and under the account's profile as Windows records
// it, neither of which the environment moves, and wherever the known-folder
// API resolves them for this process, which the environment can move but
// which is where an administrator who redirected them put them. A caller that
// keeps writes out of the Startup folders refuses all of them. A location
// that cannot be resolved is an error, because a caller cannot tell whether a
// path lies in it.
func StartupFolders() ([]string, error) {
	data, err := ProgramData.Path()
	if err != nil {
		return nil, err
	}
	profile, err := Profile()
	if err != nil {
		return nil, err
	}
	folders := []string{
		filepath.Join(append([]string{data}, startupUnderBase...)...),
		filepath.Join(append([]string{profile, "AppData", "Roaming"}, startupUnderBase...)...),
	}
	for _, f := range []Folder{commonStartup, startup} {
		resolved, err := f.Path()
		if err != nil {
			return nil, err
		}
		// Windows compares paths without regard to case.
		if !slices.ContainsFunc(folders, func(known string) bool {
			return strings.EqualFold(filepath.Clean(known), filepath.Clean(resolved))
		}) {
			folders = append(folders, resolved)
		}
	}
	return folders, nil
}
