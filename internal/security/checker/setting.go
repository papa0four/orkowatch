// internal/security/checker/setting.go

package checker

import (
	"strconv"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

type (
	// setting is one option as a configuration file states it: its value, and
	// the file and line it is on. file is relative to the root of the file
	// system read, which is how the readers take their paths.
	setting struct {
		value string
		file  string
		line  int
	}

	// programRelease is the release of an installed program whose defaults
	// differ between releases: its major and minor number, and the text they
	// were read from.
	programRelease struct {
		major, minor int
		text         string
	}
)

// at names where the setting is, as path:line.
func (s setting) at() string {
	return lineRef("/"+s.file, s.line)
}

// settingEvidence is the evidence of a setting a file states, under the name
// the program's manual gives it: its value and where it is, then whatever
// else was observed of it.
func settingEvidence(subject string, s setting, facts ...finding.Fact) finding.Evidence {
	return evidence(finding.KindSetting, subject, append([]finding.Fact{
		fact(finding.FactValue, s.value), fact(finding.FactLine, s.at()),
	}, facts...)...)
}

// unsetEvidence is the evidence of a setting no file states, so the
// program's default applies, with whatever else was observed of it.
func unsetEvidence(subject string, facts ...finding.Fact) finding.Evidence {
	return evidence(finding.KindSetting, subject, append([]finding.Fact{
		fact(finding.FactState, "not set"),
	}, facts...)...)
}

// parseRelease reads a release written as a major and a minor number with a
// dot between them and anything after, such as 1.19.2.
func parseRelease(text string) (programRelease, bool) {
	first, rest, ok := strings.Cut(text, ".")
	if !ok {
		return programRelease{}, false
	}
	second, _, _ := strings.Cut(rest, ".")
	major, errMajor := strconv.Atoi(first)
	minor, errMinor := strconv.Atoi(second)
	if errMajor != nil || errMinor != nil {
		return programRelease{}, false
	}
	return programRelease{major: major, minor: minor, text: text}, true
}

// atLeast reports whether r is the release major.minor or a later one.
func (r programRelease) atLeast(major, minor int) bool {
	return r.major > major || r.major == major && r.minor >= minor
}

// series is the release without what follows its minor number, which is how
// a distribution's builds of one release line are told apart from another's.
func (r programRelease) series() string {
	return strconv.Itoa(r.major) + "." + strconv.Itoa(r.minor)
}
