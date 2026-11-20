//go:build windows

// internal/winfolder/winfolder_windows_test.go

package winfolder

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// childEnv marks the test process started to resolve folders and print them.
const childEnv = "OWATCH_WINFOLDER_CHILD"

// folders are every exported folder, for the tests to resolve.
var folders = []Folder{Windows, System, ProgramFiles, ProgramFilesX86, ProgramData, UserProfiles}

// Every folder resolves to an absolute path that exists, the System folder
// lies inside the Windows folder, and an element is joined to the folder.
func TestFoldersResolve(t *testing.T) {
	for _, f := range folders {
		path, err := f.Path()
		if err != nil {
			t.Errorf("%s: %v", f.Name(), err)
			continue
		}
		if !filepath.IsAbs(path) {
			t.Errorf("%s resolved to %q, which is not absolute", f.Name(), path)
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s resolved to %q: %v", f.Name(), path, err)
		}
	}

	windowsDir, windowsErr := Windows.Path()
	system, systemErr := System.Path()
	if windowsErr != nil || systemErr != nil || !strings.HasPrefix(strings.ToLower(system), strings.ToLower(windowsDir)+`\`) {
		t.Errorf("System %q (%v) is not inside Windows %q (%v)", system, systemErr, windowsDir, windowsErr)
	}
	config, configErr := ProgramData.Path("ssh", "sshd_config")
	data, dataErr := ProgramData.Path()
	if configErr != nil || dataErr != nil || config != filepath.Join(data, "ssh", "sshd_config") {
		t.Errorf("joined path %q (%v), folder %q (%v)", config, configErr, data, dataErr)
	}
}

// TestChildResolve prints what a process resolves, one name and path per line.
// It runs only as the child the environment test starts.
func TestChildResolve(t *testing.T) {
	if os.Getenv(childEnv) == "" {
		t.Skip("run only as a child of TestFoldersIgnoreTheEnvironment")
	}
	for _, f := range folders {
		path, err := f.Path()
		fmt.Printf("%s\t%s\t%v\n", f.Name(), path, err)
	}
	profile, err := Profile()
	fmt.Printf("profile\t%s\t%v\n", profile, err)
	startups, err := StartupFolders()
	for _, path := range startups {
		fmt.Printf("startup\t%s\t%v\n", path, err)
	}
	if err != nil {
		fmt.Printf("startup\t\t%v\n", err)
	}
}

// resolveIn runs TestChildResolve in a new process whose environment sets each
// of set to value, and returns its lines. Windows expands the environment
// when a process first resolves a folder and keeps the answer, so only a
// process started with the change shows its effect.
func resolveIn(t *testing.T, set []string, value string) []string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestChildResolve$", "-test.v") // #nosec G204 -- the test binary itself
	cmd.Env = append(os.Environ(), childEnv+"=1")
	for _, name := range set {
		cmd.Env = append(cmd.Env, name+"="+value)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child with %v: %v\n%s", set, err, out)
	}
	var lines []string
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.Count(line, "\t") == 2 {
			lines = append(lines, line)
		}
	}
	return lines
}

// A process started with any of the variables that name these folders
// pointing elsewhere resolves every folder to the same place, and is still
// given both default Startup locations, so a Startup folder the environment
// moves is refused where it really is.
func TestFoldersIgnoreTheEnvironment(t *testing.T) {
	decoy := t.TempDir()
	for _, rel := range []string{`Microsoft\Windows\Start Menu\Programs\Startup`, `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`} {
		if err := os.MkdirAll(filepath.Join(decoy, rel), 0o750); err != nil {
			t.Fatal(err)
		}
	}

	baseline := resolveIn(t, nil, "")
	if len(baseline) != len(folders)+3 {
		t.Fatalf("baseline resolution: %q", baseline)
	}
	for _, name := range []string{"SystemRoot", "windir", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData", "ALLUSERSPROFILE", "APPDATA", "USERPROFILE", "PUBLIC"} {
		got := resolveIn(t, []string{name}, decoy)
		for _, line := range baseline {
			if !slices.Contains(got, line) {
				t.Errorf("with %s set elsewhere, %q is missing from %q", name, line, got)
			}
		}
	}
}
