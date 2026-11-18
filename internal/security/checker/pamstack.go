// internal/security/checker/pamstack.go

package checker

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
)

type (
	// pamLayout is where a host's libpam takes its configuration. dirs are the
	// service directories in the order libpam opens a service in them, and
	// atInclude is set where libpam carries Debian's @include directive, which
	// also resolves a relative include in the first directory only. Paths are
	// relative to the root of the file system read.
	pamLayout struct {
		dirs      []string
		conf      string
		atInclude bool
	}

	// pamStack reads every service's stack and records the rules that name one
	// of modules, keyed by where the rule is, with the services that reach it.
	pamStack struct {
		fsys     fs.FS
		layout   pamLayout
		modules  []string
		rules    map[pamRuleKey]map[string]bool
		order    []pamRuleKey
		reading  []string
		problems []string
	}

	// pamRuleKey identifies one rule naming a module: its type, the module's
	// file name, and the file and line the rule is on.
	pamRuleKey struct {
		typ    string
		module string
		file   string
		line   int
	}

	// pamWire is one rule naming a module, as evidence records it.
	pamWire struct {
		subject  string
		line     string
		services string
	}

	// pamRule is one rule as libpam reads it: the service field, present only
	// in pam.conf, then type, control and the module path or included file.
	pamRule struct {
		line    int
		service string
		typ     string
		control string
		target  string
	}
)

// pamTypes are the management groups pam.conf(5) lists. A rule with any other
// type is installed by libpam to fail, so it names no module.
var pamTypes = []string{"account", "auth", "password", "session"}

// readPAMStack reads the configuration of every service layout names and
// returns the rules naming one of modules, and what could not be read. libpam
// reads the service directories when any of them exists and pam.conf only when
// none does (pam_handlers.c, _pam_init_handlers).
func readPAMStack(fsys fs.FS, layout pamLayout, modules []string) *pamStack {
	s := &pamStack{fsys: fsys, layout: layout, modules: modules, rules: map[pamRuleKey]map[string]bool{}}
	services, found := s.services()
	if !found {
		s.readConf()
		return s
	}
	for _, service := range services {
		if file, ok := s.open(service, false); ok {
			s.read(file, service, "")
		}
	}
	return s
}

// services returns the name of every service file in the service
// directories, and whether any directory exists.
func (s *pamStack) services() ([]string, bool) {
	var names []string
	var found bool
	for _, dir := range s.layout.dirs {
		entries, err := fs.ReadDir(s.fsys, dir)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			found = true
			s.problem("%s could not be listed: %v", "/"+dir, err)
			continue
		}
		found = true
		for _, entry := range entries {
			if !entry.IsDir() && !slices.Contains(names, entry.Name()) {
				names = append(names, entry.Name())
			}
		}
	}
	slices.Sort(names)
	return names, found
}

// open returns the file libpam reads for name, a service or an included file.
// An absolute name is read as written. A relative one is the first of the
// service directories holding it, or, for Debian's directives, the first
// directory only (pam_handlers.c, _pam_open_config_file; Debian patch
// 031_pam_include).
func (s *pamStack) open(name string, include bool) (string, bool) {
	var candidates []string
	switch {
	case strings.HasPrefix(name, "/"):
		candidates = []string{strings.TrimPrefix(path.Clean(name), "/")}
	case include && s.layout.atInclude:
		candidates = []string{path.Join(s.layout.dirs[0], name)}
	default:
		for _, dir := range s.layout.dirs {
			candidates = append(candidates, path.Join(dir, name))
		}
	}
	for _, file := range candidates {
		if _, err := fs.Stat(s.fsys, file); err == nil {
			return file, true
		}
	}
	return "", false
}

// readConf reads pam.conf, whose rules each begin with the service they
// belong to.
func (s *pamStack) readConf() {
	data, err := fs.ReadFile(s.fsys, s.layout.conf)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return
	case err != nil:
		s.problem("%s could not be read: %v", "/"+s.layout.conf, err)
		return
	}
	rules, err := parsePAMRules(data, true)
	if err != nil {
		s.problem("%s: %v", "/"+s.layout.conf, err)
	}
	s.reading = append(s.reading, s.layout.conf)
	for _, rule := range rules {
		s.follow(rule, s.layout.conf, rule.service, "")
	}
	s.reading = s.reading[:0]
}

// read reads one file of service's stack, keeping the rules of typ, or of
// every type when typ is empty. A file already being read is not read again:
// libpam would include it without end.
func (s *pamStack) read(file, service, typ string) {
	if slices.Contains(s.reading, file) {
		s.problem("/%s is included from a file it includes; the inclusion was not followed", file)
		return
	}
	data, err := fs.ReadFile(s.fsys, file)
	if err != nil {
		s.problem("/%s could not be read: %v", file, err)
		return
	}
	rules, err := parsePAMRules(data, false)
	if err != nil {
		s.problem("/%s: %v", file, err)
	}
	s.reading = append(s.reading, file)
	defer func() { s.reading = s.reading[:len(s.reading)-1] }()
	for _, rule := range rules {
		s.follow(rule, file, service, typ)
	}
}

// follow records a rule naming one of the modules, or reads the file a rule
// includes. A type libpam does not know installs a rule that fails, which
// names no module; Debian's @include stands in the type field and includes the
// requested type, or every type at the top of a stack.
func (s *pamStack) follow(rule pamRule, file, service, typ string) {
	ruleType := strings.ToLower(strings.TrimPrefix(rule.typ, "-"))
	switch {
	case ruleType == "@include" && s.layout.atInclude:
		s.include(rule.control, file, service, typ)
		return
	case !slices.Contains(pamTypes, ruleType):
		return
	case typ != "" && ruleType != typ:
		return
	}
	switch strings.ToLower(rule.control) {
	case "include", "substack":
		s.include(rule.target, file, service, ruleType)
	default:
		module := path.Base(rule.target)
		if rule.target == "" || !slices.Contains(s.modules, module) {
			return
		}
		key := pamRuleKey{typ: ruleType, module: module, file: file, line: rule.line}
		if s.rules[key] == nil {
			s.rules[key] = map[string]bool{}
			s.order = append(s.order, key)
		}
		s.rules[key][service] = true
	}
}

// include reads the file name names, as part of the stack file is in.
func (s *pamStack) include(name, file, service, typ string) {
	if name == "" {
		s.problem("/%s includes no file", file)
		return
	}
	target, ok := s.open(name, true)
	if !ok {
		s.problem("/%s includes %s, which is not present", file, name)
		return
	}
	s.read(target, service, typ)
}

// problem records what could not be read or followed, once however many
// services or rule types reach it.
func (s *pamStack) problem(format string, args ...any) {
	if text := fmt.Sprintf(format, args...); !slices.Contains(s.problems, text) {
		s.problems = append(s.problems, text)
	}
}

// parsePAMRules splits a PAM configuration file into rules as libpam reads it
// (pam_handlers.c, _pam_assemble_line and _pam_parse_conf_file; pam_misc.c,
// _pam_StrTok). Blank lines and lines beginning with # are skipped, text from
// # to the end of a line is a comment, and a line ending in a backslash is
// joined to the next. Tokens are separated by spaces and tabs, and a token
// beginning with [ runs to the first ], with \] standing for ]. A rule's line
// is the first line it is written on. A file ending inside a joined line is an
// error, which libpam also reports, with the rules before it returned.
func parsePAMRules(data []byte, withService bool) ([]pamRule, error) {
	var rules []pamRule
	var joined strings.Builder
	first := 0
	for i, raw := range strings.Split(string(data), "\n") {
		text := strings.TrimLeft(raw, " \t")
		if text == "" || text[0] == '#' {
			continue
		}
		if first == 0 {
			first = i + 1
		}
		if comment := strings.IndexByte(text, '#'); comment >= 0 {
			joined.WriteString(text[:comment])
		} else if trimmed := strings.TrimRight(text, " \t\r"); strings.HasSuffix(trimmed, `\`) {
			joined.WriteString(strings.TrimSuffix(trimmed, `\`) + " ")
			continue
		} else {
			joined.WriteString(trimmed)
		}
		if rule, ok := splitPAMRule(joined.String(), withService); ok {
			rule.line = first
			rules = append(rules, rule)
		}
		joined.Reset()
		first = 0
	}
	if first != 0 {
		return rules, fmt.Errorf("line %d is continued past the end of the file", first)
	}
	return rules, nil
}

// splitPAMRule takes the fields of one rule from its text.
func splitPAMRule(text string, withService bool) (pamRule, bool) {
	tokens := pamTokens(text)
	var rule pamRule
	if withService {
		if len(tokens) == 0 {
			return rule, false
		}
		rule.service, tokens = tokens[0], tokens[1:]
	}
	fields := []*string{&rule.typ, &rule.control, &rule.target}
	for i := range fields {
		if i < len(tokens) {
			*fields[i] = tokens[i]
		}
	}
	return rule, rule.typ != ""
}

// pamTokens splits text as _pam_StrTok does.
func pamTokens(text string) []string {
	var tokens []string
	for {
		text = strings.TrimLeft(text, " \t")
		if text == "" {
			return tokens
		}
		if text[0] != '[' {
			end := strings.IndexAny(text, " \t")
			if end < 0 {
				end = len(text)
			}
			tokens = append(tokens, text[:end])
			text = text[end:]
			continue
		}
		var token strings.Builder
		i := 1
		for ; i < len(text) && text[i] != ']'; i++ {
			if text[i] == '\\' && i+1 < len(text) && text[i+1] == ']' {
				i++
			}
			token.WriteByte(text[i])
		}
		tokens = append(tokens, token.String())
		if i < len(text) {
			i++
		}
		text = text[i:]
	}
}

// wiring returns, for each rule naming module, its subject, its line and the
// services that reach it, in the order the rules were first reached.
func (s *pamStack) wiring(module string) []pamWire {
	var out []pamWire
	for _, key := range s.order {
		if key.module != module {
			continue
		}
		services := make([]string, 0, len(s.rules[key]))
		for service := range s.rules[key] {
			services = append(services, service)
		}
		slices.Sort(services)
		out = append(out, pamWire{
			subject:  key.typ + " " + key.module,
			line:     lineRef("/"+key.file, key.line),
			services: strings.Join(services, ", "),
		})
	}
	return out
}
