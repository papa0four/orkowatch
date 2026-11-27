// internal/dataset/osv/release.go

package osv

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/papa0four/orkowatch/internal/dataset"
)

// release is a release of a distribution as OSV's records name it: the name
// kept data is labeled with, and which of a record's ecosystems are this
// release's. Each distribution's release is named from the platform version
// its hosts report, as read on a host of each on 2026-11-24.
type release struct {
	name    string
	accepts func(ecosystem string) bool
}

var (
	// ubuntuVersion is an Ubuntu release as its hosts report it, 22.04.
	ubuntuVersion = regexp.MustCompile(`^[0-9]{2}\.[0-9]{2}$`)

	// dotted is a version of numbers parted by dots, as 3.20.10 or 9.9.
	dotted = regexp.MustCompile(`^[0-9]{1,4}(\.[0-9]{1,6}){0,3}$`)
)

// firstOwnReleaseNamed is the first major release of Red Hat Enterprise Linux
// whose records are named by minor release, enterprise_linux:10.3, where
// those before it are named by major release and repository,
// enterprise_linux:9::appstream.
const firstOwnReleaseNamed = 10

// ubuntu is the plain release of an Ubuntu version, which OSV names
// Ubuntu:22.04:LTS for a long-term release and Ubuntu:25.10 for another. Pro,
// FIPS, Realtime, and BlueField streams are not this release: a host's
// version does not show them.
func ubuntu(version string) (release, error) {
	if !ubuntuVersion.MatchString(version) {
		return release{}, notRelease("Ubuntu", version)
	}
	name := "Ubuntu:" + version
	return release{name: name, accepts: func(eco string) bool { return eco == name || eco == name+":LTS" }}, nil
}

// alpine is the Alpine release of a version, its major and minor numbers:
// 3.20.10 is Alpine:v3.20.
func alpine(version string) (release, error) {
	parts, err := numbers("Alpine", version, 2)
	if err != nil {
		return release{}, err
	}
	return exact(fmt.Sprintf("Alpine:v%d.%d", parts[0], parts[1])), nil
}

// major returns the release of a version of the distribution OSV names
// distribution, its major number: 9.9 is AlmaLinux:9.
func major(distribution string) func(string) (release, error) {
	return func(version string) (release, error) {
		parts, err := numbers(distribution, version, 1)
		if err != nil {
			return release{}, err
		}
		return exact(fmt.Sprintf("%s:%d", distribution, parts[0])), nil
	}
}

// redHat is the release of a version of Red Hat Enterprise Linux: every
// repository's stream of its major release, enterprise_linux:9::appstream and
// the others, and from release 10 on, the stream of its minor release,
// enterprise_linux:10.3, with any repository stream of its major release.
// Extended-support streams are not the release: a host's version does not
// show them.
func redHat(version string) (release, error) {
	parts, err := numbers("Red Hat Enterprise Linux", version, 2)
	if err != nil {
		return release{}, err
	}
	streams := fmt.Sprintf("Red Hat:enterprise_linux:%d::", parts[0])
	if parts[0] < firstOwnReleaseNamed {
		name := strings.TrimSuffix(streams, "::")
		return release{name: name, accepts: func(eco string) bool { return strings.HasPrefix(eco, streams) }}, nil
	}
	name := fmt.Sprintf("Red Hat:enterprise_linux:%d.%d", parts[0], parts[1])
	return release{name: name, accepts: func(eco string) bool { return eco == name || strings.HasPrefix(eco, streams) }}, nil
}

// exact is the release named name and no other.
func exact(name string) release {
	return release{name: name, accepts: func(eco string) bool { return eco == name }}
}

// numbers reads at least want numbers from a dotted version of distribution.
func numbers(distribution, version string, want int) ([]int, error) {
	if !dotted.MatchString(version) {
		return nil, notRelease(distribution, version)
	}
	fields := strings.Split(version, ".")
	if len(fields) < want {
		return nil, notRelease(distribution, version)
	}
	parts := make([]int, len(fields))
	for i, f := range fields {
		n, err := strconv.Atoi(f)
		if err != nil {
			return nil, notRelease(distribution, version)
		}
		parts[i] = n
	}
	return parts, nil
}

// notRelease is the refusal of a version that names no release.
func notRelease(distribution, version string) error {
	return fmt.Errorf("the version %q names no release of %s", dataset.Printable(version), distribution)
}
