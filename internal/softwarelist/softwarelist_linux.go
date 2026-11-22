//go:build linux

// internal/softwarelist/softwarelist_linux.go

package softwarelist

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// Where the package managers that are read from their own files keep what is
// installed, and how the ones that are asked are asked.
const (
	// dpkgFormat asks dpkg-query for the fields dpkg-query(1) names: the
	// package and its version, its architecture, "the source package name
	// for this binary package" and "the source package version for this
	// binary package", and "the package status word".
	dpkgFormat = "${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${db:Status-Status}\n"

	// dpkgInstalled is the status word of a package that is installed. A
	// package removed with its configuration left behind stays in dpkg's
	// database under another word, and is not software on the host.
	dpkgInstalled = "installed"

	// rpmFormat asks rpm for the tags rpm --querytags lists. A tag with no
	// value prints as rpmNone.
	rpmFormat = "%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n"
	rpmNone   = "(none)"

	// rpmPublicKey is the name rpm gives an imported signing key, which it
	// keeps in the package database with no architecture and no source. It
	// is a key, not software.
	rpmPublicKey = "gpg-pubkey"

	// rpmSourceSuffixes end the file name of a source package, and the two
	// fields before them, each set off by a hyphen, are its version and
	// release.
	rpmSourceSuffix   = ".src.rpm"
	rpmNoSourceSuffix = ".nosrc.rpm"
	rpmSourceFields   = 2

	// apkInstalled is apk's database of installed packages: records apart
	// by a blank line, each line a letter, a colon and a value. The letters
	// are the ones apk-package(5) gives: P the name, V the version, A the
	// architecture, and o the origin, "Package's source package name".
	apkInstalled = "/lib/apk/db/installed"

	// pacmanLocal is pacman's database of installed packages: a directory
	// for each, holding a desc file of sections, each a name between
	// percent signs on one line and its value on the next.
	pacmanLocal = "/var/lib/pacman/local"
	pacmanDesc  = "desc"

	fieldSeparator = "\t"
)

// The fields of one line of each manager's answer.
const (
	dpkgName = iota
	dpkgVersion
	dpkgArch
	dpkgSource
	dpkgSourceVersion
	dpkgStatus
	dpkgFields
)

const (
	rpmName = iota
	rpmEpoch
	rpmVersion
	rpmRelease
	rpmArch
	rpmSourceRPM
	rpmFields
)

// getPlatformSoftwareList reads every package manager the host has, since a
// host can carry more than one. A manager that is not there is passed over; a
// manager that is there and cannot be read fails the inventory, because a
// list missing a manager's packages would read as a host without them.
func getPlatformSoftwareList(ctx context.Context) ([]SoftwareEntry, error) {
	readers := []func(context.Context) ([]SoftwareEntry, bool, error){readDpkg, readRPM, readAPK, readPacman}

	var entries []SoftwareEntry
	var found bool
	for _, read := range readers {
		list, present, err := read(ctx)
		if err != nil {
			return nil, err
		}
		found = found || present
		entries = append(entries, list...)
	}
	if !found {
		return nil, errors.New("no supported package manager found: dpkg, rpm, apk and pacman are read")
	}

	// rpm lists packages in no order of its own, and a report must not
	// change from run to run.
	slices.SortFunc(entries, func(a, b SoftwareEntry) int {
		return cmp.Or(strings.Compare(a.Manager, b.Manager), strings.Compare(a.Name, b.Name),
			strings.Compare(a.Architecture, b.Architecture), strings.Compare(a.Version, b.Version))
	})
	return entries, nil
}

// readDpkg asks dpkg-query for every package it knows.
func readDpkg(ctx context.Context) ([]SoftwareEntry, bool, error) {
	output, present, err := ask(ctx, "dpkg-query", "-W", "-f="+dpkgFormat)
	if err != nil || !present {
		return nil, present, err
	}
	entries, err := parseDpkg(string(output))
	return entries, true, err
}

// readRPM asks rpm for every package in its database.
func readRPM(ctx context.Context) ([]SoftwareEntry, bool, error) {
	output, present, err := ask(ctx, "rpm", "-qa", "--queryformat", rpmFormat)
	if err != nil || !present {
		return nil, present, err
	}
	entries, err := parseRPM(string(output))
	return entries, true, err
}

// ask runs a package manager's query. It reports the manager absent when its
// program is not on the host.
func ask(ctx context.Context, program string, args ...string) (output []byte, present bool, err error) {
	output, err = exec.CommandContext(ctx, program, args...).Output() // #nosec G204 -- fixed program and arguments
	switch {
	case errors.Is(err, exec.ErrNotFound):
		return nil, false, nil
	case err != nil:
		return nil, true, fmt.Errorf("%s: %w", program, err)
	}
	return output, true, nil
}

// readAPK reads apk's database of installed packages.
func readAPK(context.Context) ([]SoftwareEntry, bool, error) {
	data, err := os.ReadFile(apkInstalled)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, false, nil
	case err != nil:
		return nil, true, fmt.Errorf("apk: %w", err)
	}
	return parseAPK(string(data)), true, nil
}

// readPacman reads the desc file of every package in pacman's database.
func readPacman(ctx context.Context) ([]SoftwareEntry, bool, error) {
	packages, err := os.ReadDir(pacmanLocal)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, false, nil
	case err != nil:
		return nil, true, fmt.Errorf("pacman: %w", err)
	}

	var entries []SoftwareEntry
	for _, pkg := range packages {
		if err := ctx.Err(); err != nil {
			return nil, true, err
		}
		if !pkg.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(pacmanLocal, pkg.Name(), pacmanDesc)) // #nosec G304 -- a directory of pacman's own database
		if err != nil {
			return nil, true, fmt.Errorf("pacman: %w", err)
		}
		entry, err := parsePacmanDesc(string(data))
		if err != nil {
			return nil, true, fmt.Errorf("pacman: %s: %w", pkg.Name(), err)
		}
		entries = append(entries, entry)
	}
	return entries, true, nil
}

// parseDpkg reads dpkg-query's answer, keeping the packages that are
// installed. The version of a binary package can differ from its source's:
// a rebuild adds a suffix and a binary package can carry an epoch its source
// does not, so both are kept as dpkg states them.
func parseDpkg(output string) ([]SoftwareEntry, error) {
	var entries []SoftwareEntry
	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, fieldSeparator)
		if len(fields) != dpkgFields || fields[dpkgName] == "" {
			return nil, fmt.Errorf("dpkg-query: unexpected line %q", line)
		}
		if fields[dpkgStatus] != dpkgInstalled {
			continue
		}
		entries = append(entries, SoftwareEntry{
			Name:          fields[dpkgName],
			Version:       fields[dpkgVersion],
			Manager:       ManagerDpkg,
			Architecture:  fields[dpkgArch],
			Source:        fields[dpkgSource],
			SourceVersion: fields[dpkgSourceVersion],
		})
	}
	return entries, nil
}

// parseRPM reads rpm's answer. The version is written the way rpm writes a
// package's, the epoch and a colon ahead of the version when there is one and
// the release after a hyphen, which is the form a fixed version is given in.
// The source is the name in the source package's file name; its version is
// not kept, since the file name does not carry the epoch.
func parseRPM(output string) ([]SoftwareEntry, error) {
	var entries []SoftwareEntry
	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, fieldSeparator)
		if len(fields) != rpmFields || fields[rpmName] == "" {
			return nil, fmt.Errorf("rpm: unexpected line %q", line)
		}
		if fields[rpmName] == rpmPublicKey {
			continue
		}

		version := fields[rpmVersion] + "-" + fields[rpmRelease]
		if epoch := fields[rpmEpoch]; epoch != rpmNone {
			version = epoch + ":" + version
		}
		entry := SoftwareEntry{
			Name:    fields[rpmName],
			Version: version,
			Manager: ManagerRPM,
			Source:  rpmSourceName(fields[rpmSourceRPM]),
		}
		if arch := fields[rpmArch]; arch != rpmNone {
			entry.Architecture = arch
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// rpmSourceName returns the package name in the file name of a source
// package, name-version-release.src.rpm, or empty when rpm gave none or the
// name is not of that form.
func rpmSourceName(file string) string {
	base, found := strings.CutSuffix(file, rpmSourceSuffix)
	if !found {
		if base, found = strings.CutSuffix(file, rpmNoSourceSuffix); !found {
			return ""
		}
	}
	for range rpmSourceFields {
		cut := strings.LastIndexByte(base, '-')
		if cut <= 0 {
			return ""
		}
		base = base[:cut]
	}
	return base
}

// parseAPK reads apk's database. A record with no name is not a package and
// is passed over, as the lines of a record that list its files are.
func parseAPK(data string) []SoftwareEntry {
	var entries []SoftwareEntry
	entry := SoftwareEntry{Manager: ManagerAPK}
	keep := func() {
		if entry.Name != "" {
			entries = append(entries, entry)
		}
		entry = SoftwareEntry{Manager: ManagerAPK}
	}

	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			keep()
			continue
		}
		letter, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch letter {
		case "P":
			entry.Name = value
		case "V":
			entry.Version = value
		case "A":
			entry.Architecture = value
		case "o":
			entry.Source = value
		}
	}
	keep()
	return entries
}

// parsePacmanDesc reads one package's desc file. BASE is what PKGBUILD(5)
// calls pkgbase, "the name used to refer to the group of packages" built
// together, and VERSION is the full version string, the epoch and a colon
// ahead of pkgver-pkgrel when the epoch is not zero.
func parsePacmanDesc(data string) (SoftwareEntry, error) {
	entry := SoftwareEntry{Manager: ManagerPacman}
	sections := map[string]*string{
		"%NAME%":    &entry.Name,
		"%VERSION%": &entry.Version,
		"%BASE%":    &entry.Source,
		"%ARCH%":    &entry.Architecture,
	}

	lines := strings.Split(data, "\n")
	for i := 0; i+1 < len(lines); i++ {
		if field, wanted := sections[strings.TrimSpace(lines[i])]; wanted {
			*field = strings.TrimSpace(lines[i+1])
			i++
		}
	}
	if entry.Name == "" || entry.Version == "" {
		return SoftwareEntry{}, errors.New("desc names no package or no version")
	}
	return entry, nil
}
