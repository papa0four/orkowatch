// internal/security/checker/krb5conf.go

package checker

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/registry"
)

// The section the judged relations are in. The library matches section and
// relation names as written.
const krb5Libdefaults = "libdefaults"

type (
	// krb5Config is the [libdefaults] section as the MIT library assembles it
	// from krb5.conf and every file it includes. Each relation holds its first
	// value, which is the one the library uses. refused says why the library
	// does not start with this configuration, and undecided names each relation
	// whose value in force depends on the release, with the reason.
	krb5Config struct {
		files       []string
		libdefaults map[string]setting
		refused     []string
		undecided   map[string]string
	}

	// krb5Parser reads a configuration the way the library does. reading is
	// the chain of files being read, which is how an include that leads back to
	// a file already being read is refused. closed is set once a [libdefaults]
	// section marked final has ended.
	krb5Parser struct {
		fsys    fs.FS
		config  krb5Config
		reading includeChain
		closed  bool
	}

	// krb5Scope is where the parser is within a file: the section, whether
	// its header marked it final, and how many subsections are open.
	krb5Scope struct {
		section string
		final   bool
		depth   int
	}
)

// krb5ConfigFiles returns the configuration files the library of a host of
// families reads, of those present, in the order it reads them:
// /etc/krb5.conf; on the SUSE family /usr/etc/krb5.conf where that is absent;
// on Alpine both, /etc/krb5.conf first. Each is as the library on that family
// was seen to behave.
func krb5ConfigFiles(fsys fs.FS, families []registry.Distro) ([]string, error) {
	candidates := []string{"etc/krb5.conf"}
	if krb5ReadsVendorFile(families) {
		candidates = append(candidates, krb5VendorFile)
	}
	var present []string
	for _, file := range candidates {
		_, err := fs.Stat(fsys, file)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return nil, err
		}
		present = append(present, file)
	}
	if len(present) > 1 && !slices.Contains(families, registry.DistroAlpine) {
		present = present[:1]
	}
	return present, nil
}

// readKrb5Config reads files in order, with every file they include, by the
// rules of krb5.conf(5) and, where it is silent, as the library was seen to
// behave: the first value of a relation is the one used, an include is read
// where it is written, and a value runs to the end of its line.
func readKrb5Config(fsys fs.FS, files []string) (krb5Config, error) {
	p := &krb5Parser{fsys: fsys, config: krb5Config{
		files:       files,
		libdefaults: map[string]setting{},
		undecided:   map[string]string{},
	}}
	for _, file := range files {
		data, err := fs.ReadFile(fsys, file)
		if err != nil {
			return p.config, err
		}
		p.reading = includeChain{file}
		p.parse(file, data)
	}
	return p.config, nil
}

// parse reads one file. A line is a comment, a directive at its very
// beginning, a section header, a relation, or a brace closing a subsection;
// the library refuses any other.
func (p *krb5Parser) parse(file string, data []byte) {
	var scope krb5Scope
	for i, raw := range strings.Split(string(data), "\n") {
		raw = strings.TrimRight(raw, "\r")
		text := strings.TrimSpace(raw)
		at := lineRef("/"+file, i+1)
		directive, argument := raw, ""
		if end := strings.IndexAny(raw, " \t"); end > 0 {
			directive, argument = raw[:end], raw[end:]
		}
		switch {
		case text == "" || text[0] == '#' || text[0] == ';':
		case directive == "include" || directive == "includedir":
			p.include(directive, strings.TrimSpace(argument), at)
		case directive == "module":
			p.refuse("%s takes the configuration from a loadable module, which is not read", at)
		case text[0] == '[':
			p.header(&scope, text, at)
		case text[0] == '}':
			scope.depth = max(scope.depth-1, 0)
		default:
			p.relation(&scope, text, setting{file: file, line: i + 1})
		}
	}
	p.leave(scope)
}

// header starts the section a header line names. A star after the closing
// bracket marks the section final.
func (p *krb5Parser) header(scope *krb5Scope, text, at string) {
	p.leave(*scope)
	name, mark, closed := strings.Cut(text[1:], "]")
	if !closed {
		p.refuse("%s is a section header that is not closed", at)
		return
	}
	*scope = krb5Scope{section: name, final: strings.HasPrefix(strings.TrimSpace(mark), "*")}
}

// leave notes that a [libdefaults] section marked final has ended.
func (p *krb5Parser) leave(scope krb5Scope) {
	if scope.final && scope.section == krb5Libdefaults {
		p.closed = true
	}
}

// relation reads a line that is neither a comment, a directive nor a header.
// Only relations directly inside [libdefaults] are kept: a subsection there
// holds settings for one realm.
func (p *krb5Parser) relation(scope *krb5Scope, text string, at setting) {
	tag, value, ok := strings.Cut(text, "=")
	if !ok {
		p.refuse("%s is neither a section, a relation nor a directive", at.at())
		return
	}
	value = strings.TrimSpace(value)
	switch {
	case strings.HasPrefix(value, "{"):
		scope.depth++
	case scope.section == krb5Libdefaults && scope.depth == 0:
		at.value = unquote(value)
		p.set(strings.TrimSuffix(strings.TrimSpace(tag), "*"), at)
	}
}

// set keeps a relation's first value. One first set after a [libdefaults]
// section marked final is used before release 1.22 and ignored from it
// (krb5.conf(5)), so which holds is left undecided.
func (p *krb5Parser) set(tag string, first setting) {
	if _, ok := p.config.libdefaults[tag]; ok {
		return
	}
	p.config.libdefaults[tag] = first
	if p.closed {
		p.config.undecided[tag] = fmt.Sprintf(
			"%s is first set at %s, after a [libdefaults] section marked final, which the library honours within a file only from release 1.22",
			tag, first.at())
	}
}

// include reads the file or directory a directive names, in place. A
// directory gives "all files within the directory whose names consist solely
// of alphanumeric characters, dashes, or underscores" and those ending in
// .conf that do not begin with a dot, "read in alphanumeric order"
// (krb5.conf(5)), which is the order of their bytes. The library does not
// start when what is named cannot be read.
func (p *krb5Parser) include(directive, name, at string) {
	target := strings.TrimPrefix(path.Clean(name), "/")
	if !strings.HasPrefix(name, "/") {
		p.refuse("%s includes %q, which is not an absolute path", at, name)
		return
	}
	if directive == "include" {
		p.includeFile(target, at)
		return
	}
	entries, err := fs.ReadDir(p.fsys, target)
	if err != nil {
		p.refuse("%s includes the directory %s, which could not be read: %v", at, name, err)
		return
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && krb5Included(entry.Name()) {
			names = append(names, entry.Name())
		}
	}
	slices.Sort(names)
	for _, entry := range names {
		p.includeFile(path.Join(target, entry), at)
	}
}

// includeFile reads one included file. It is syntactically independent of the
// file including it, so it starts outside any section.
func (p *krb5Parser) includeFile(file, at string) {
	leave, ok := p.reading.enter(file)
	if !ok {
		p.refuse("%s includes /%s, which leads back to a file already being read", at, file)
		return
	}
	defer leave()

	data, err := fs.ReadFile(p.fsys, file)
	if err != nil {
		p.refuse("%s includes /%s, which could not be read: %v", at, file, err)
		return
	}
	p.config.files = append(p.config.files, file)
	p.parse(file, data)
}

// refuse records why the library does not start with this configuration.
func (p *krb5Parser) refuse(format string, args ...any) {
	p.config.refused = append(p.config.refused, fmt.Sprintf(format, args...))
}

// krb5Included reports whether an included directory gives the file name.
func krb5Included(name string) bool {
	if strings.HasSuffix(name, ".conf") && !strings.HasPrefix(name, ".") {
		return true
	}
	for _, r := range name {
		plain := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_'
		if !plain {
			return false
		}
	}
	return name != ""
}

// unquote removes the double quotes the library allows around a value.
func unquote(value string) string {
	const quoted = 2
	if len(value) >= quoted && value[0] == '"' && value[len(value)-1] == '"' {
		return value[1 : len(value)-1]
	}
	return value
}

// krb5Bool reads a boolean relation. The values are those the library was
// seen to accept, without regard to case; it does not start on any other.
func krb5Bool(value string) (bool, bool) {
	switch strings.ToLower(value) {
	case "y", "yes", "true", "t", "1", "on":
		return true, true
	case "n", "no", "false", "nil", "0", "off":
		return false, true
	}
	return false, false
}

// parseKrb5Release reads the release klist -V prints, such as "Kerberos 5
// version 1.19.2".
func parseKrb5Release(output string) (programRelease, error) {
	fields := strings.Fields(output)
	if len(fields) == 0 {
		return programRelease{}, errors.New("klist -V printed nothing")
	}
	release, ok := parseRelease(fields[len(fields)-1])
	if !ok {
		return programRelease{}, fmt.Errorf("klist -V printed %q, which names no release", strings.TrimSpace(output))
	}
	return release, nil
}
