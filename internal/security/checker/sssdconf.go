// internal/security/checker/sssdconf.go

package checker

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// Where SSSD reads its configuration, relative to the root of the file
// system read.
const (
	sssdConfFile   = "etc/sssd/sssd.conf"
	sssdSnippetDir = "etc/sssd/conf.d"
)

type (
	// sssdSetting is one option as a file states it.
	sssdSetting struct {
		value string
		file  string
		line  int
	}

	// sssdConfig is the configuration SSSD assembles from sssd.conf and the
	// snippets in conf.d (sssd.conf(5)). files are the files read, in the
	// order SSSD applies them. Each option holds every setting of it in that
	// order, so the last is the one in force and the earlier ones show which
	// files disagree. malformed says why a file could not be read as the
	// manual describes, in which case what SSSD takes from it is not known.
	sssdConfig struct {
		files     []string
		sections  map[string]map[string][]sssdSetting
		malformed []string
	}

	// sssdVersion is the release of SSSD installed, which decides the defaults
	// and the file ownership its manual states.
	sssdVersion struct {
		major, minor int
		text         string
	}
)

// readSSSDConfig reads sssd.conf and then every snippet in conf.d whose name
// ends in .conf and does not begin with a dot, in the order of their names: a
// snippet overrides sssd.conf, and a later snippet an earlier one
// (sssd.conf(5)). It returns fs.ErrNotExist when there is neither a file nor a
// snippet.
func readSSSDConfig(fsys fs.FS) (sssdConfig, error) {
	config := sssdConfig{sections: map[string]map[string][]sssdSetting{}}
	if _, err := fs.Stat(fsys, sssdConfFile); err == nil {
		config.files = append(config.files, sssdConfFile)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return config, err
	}

	snippets, err := sssdSnippets(fsys)
	if err != nil {
		return config, err
	}
	config.files = append(config.files, snippets...)
	if len(config.files) == 0 {
		return config, fs.ErrNotExist
	}

	for _, file := range config.files {
		data, err := fs.ReadFile(fsys, file)
		if err != nil {
			return config, err
		}
		config.parse(file, data)
	}
	return config, nil
}

// sssdSnippets returns the snippets SSSD reads from conf.d, in the order of
// their names: "Any file placed in conf.d that ends in ".conf" and does not
// begin with a dot" (sssd.conf(5)). A host with no conf.d has none.
func sssdSnippets(fsys fs.FS) ([]string, error) {
	entries, err := fs.ReadDir(fsys, sssdSnippetDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	var snippets []string
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() && strings.HasSuffix(name, ".conf") && !strings.HasPrefix(name, ".") {
			snippets = append(snippets, path.Join(sssdSnippetDir, name))
		}
	}
	slices.Sort(snippets)
	return snippets, nil
}

// parse adds one file's settings. The syntax is the one sssd.conf(5) gives: a
// section name in square brackets, key = value, and a comment line beginning
// with # or ;. Inline comments are not supported, so the value runs to the end
// of the line.
func (c *sssdConfig) parse(file string, data []byte) {
	section := ""
	for i, raw := range strings.Split(string(data), "\n") {
		text := strings.TrimSpace(raw)
		switch {
		case text == "" || text[0] == '#' || text[0] == ';':
		case text[0] == '[' && strings.HasSuffix(text, "]"):
			section = strings.TrimSpace(text[1 : len(text)-1])
		default:
			key, value, ok := strings.Cut(text, "=")
			if !ok || section == "" {
				c.malformed = append(c.malformed,
					lineRef("/"+file, i+1)+" is neither a section nor a key = value inside one")
				continue
			}
			key = strings.TrimSpace(key)
			if c.sections[section] == nil {
				c.sections[section] = map[string][]sssdSetting{}
			}
			c.sections[section][key] = append(c.sections[section][key],
				sssdSetting{value: strings.TrimSpace(value), file: file, line: i + 1})
		}
	}
}

// get returns the setting of key in section that is in force, and whether any
// file sets it.
func (c sssdConfig) get(section, key string) (sssdSetting, bool) {
	settings := c.sections[section][key]
	if len(settings) == 0 {
		return sssdSetting{}, false
	}
	return settings[len(settings)-1], true
}

// undecided reports whether which setting of key is in force depends on the
// locale. sssd.conf(5) orders snippets "in alphabetical order (based on
// locale)", and a locale's order ignores case and punctuation where the order
// of bytes does not. Two snippets that set the option differently are in a
// known order only when their names compare the same way both ways.
func (c sssdConfig) undecided(section, key string) bool {
	settings := c.sections[section][key]
	if len(settings) == 0 {
		return false
	}
	last := settings[len(settings)-1]
	for _, other := range settings[:len(settings)-1] {
		if other.file == sssdConfFile || other.file == last.file || other.value == last.value {
			continue
		}
		if a, b := collationKey(other.file), collationKey(last.file); a >= b {
			return true
		}
	}
	return false
}

// collationKey is name as a locale's first comparison sees it: letters and
// digits only, without regard to case.
func collationKey(name string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, path.Base(name))
}

// activeDomains returns the domains SSSD serves, in the order first named: a
// domain "is enabled only if it is listed in the domains option in the [sssd]
// section", unless its own enabled option says otherwise (sssd.conf(5)).
func (c sssdConfig) activeDomains() []string {
	var names []string
	if listed, ok := c.get("sssd", "domains"); ok {
		for _, name := range strings.Split(listed.value, ",") {
			if name = strings.TrimSpace(name); name != "" && !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	var sections []string
	for section := range c.sections {
		sections = append(sections, section)
	}
	slices.Sort(sections)
	for _, section := range sections {
		name, isDomain := strings.CutPrefix(section, "domain/")
		if !isDomain || strings.Contains(name, "/") {
			continue
		}
		enabled, set := c.get(section, "enabled")
		switch {
		case set && strings.EqualFold(enabled.value, "false"):
			names = slices.DeleteFunc(names, func(n string) bool { return n == name })
		case set && strings.EqualFold(enabled.value, "true") && !slices.Contains(names, name):
			names = append(names, name)
		}
	}
	return slices.DeleteFunc(names, func(name string) bool { return c.sections["domain/"+name] == nil })
}

// sssdBool reads a boolean option, which sssd.conf(5) writes as TRUE or FALSE.
func sssdBool(value string) (bool, bool) {
	switch strings.ToLower(value) {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

// parseSSSDVersion reads the release sssd --version prints, such as 2.9.9.
func parseSSSDVersion(output string) (sssdVersion, error) {
	text := strings.TrimSpace(output)
	parts := strings.Split(text, ".")
	const majorMinor = 2
	if len(parts) < majorMinor {
		return sssdVersion{}, fmt.Errorf("sssd --version printed %q, which is not a release", text)
	}
	major, errMajor := strconv.Atoi(parts[0])
	minor, errMinor := strconv.Atoi(parts[1])
	if errMajor != nil || errMinor != nil {
		return sssdVersion{}, fmt.Errorf("sssd --version printed %q, which is not a release", text)
	}
	return sssdVersion{major: major, minor: minor, text: text}, nil
}

// runsAsServiceUser reports whether v is SSSD 2.10.0 or later. From that
// release the service runs as the sssd user and its configuration may belong
// to that user, and ldap_id_use_start_tls defaults to true; before it the
// configuration is root's alone and the default is false (SSSD 2.10.0 release
// notes).
func (v sssdVersion) runsAsServiceUser() bool {
	const major, minor = 2, 10
	return v.major > major || v.major == major && v.minor >= minor
}
