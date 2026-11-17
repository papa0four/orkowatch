// internal/security/checker/ssh.go

package checker

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
)

type (
	// SSHChecker is the SSH configuration check as the audit sees it. Each
	// platform supplies NewSSHChecker under its own build constraint.
	SSHChecker interface {
		Name() string
		Description() string
		Check(ctx context.Context) finding.AuditResult
	}

	// sshConfig is the server configuration as sshd assembles it from the
	// main file and every file it includes. global holds the first value of
	// each keyword outside any Match block, which is the one sshd uses;
	// blocks hold the keywords a Match block sets for the connections it
	// matches. Keywords are lower case, because sshd matches them without
	// regard to case.
	sshConfig struct {
		global map[string]sshSetting
		blocks []sshMatchBlock
	}

	// sshMatchBlock is one Match block: its criteria as written and the first
	// value of each keyword set inside it.
	sshMatchBlock struct {
		criteria string
		settings map[string]sshSetting
	}

	// sshSetting is one directive as the configuration states it. found
	// distinguishes an explicit setting from an absent one, which warrant
	// different conclusions because sshd applies its own default to what the
	// configuration does not say. rejected states why sshd refuses the line,
	// in which case the server does not start with this configuration.
	sshSetting struct {
		value    string
		found    bool
		rejected string
	}

	// sshdParser reads a configuration the way sshd does. dir is where a
	// relative Include is resolved, and reading is the chain of files being
	// read, which is how an Include that leads back to a file already being
	// read is refused rather than followed forever.
	sshdParser struct {
		dir     string
		config  sshConfig
		reading []string
	}

	// sshRule pairs a directive with the rules it decides. absentKey is empty
	// on platforms with no rule defined for the directive being unset.
	sshRule struct {
		name      string
		unsafe    func(value string) bool
		unsafeKey registry.FindingKey
		absentKey registry.FindingKey
	}

	// sshdAbsentKeys names the findings a platform defines for the two
	// evaluated directives being unset. A zero value means the platform has
	// no such definitions and an unset directive is not reported.
	sshdAbsentKeys struct {
		rootLogin    registry.FindingKey
		passwordAuth registry.FindingKey
	}
)

// The keywords the parser acts on, in the lower case it compares them in.
const (
	keywordInclude      = "include"
	keywordMatch        = "match"
	keywordRootLogin    = "permitrootlogin"
	keywordPasswordAuth = "passwordauthentication"
)

// sshdValues lists, for each directive the audit judges, the values sshd
// accepts for it, as sshd -T reports them accepted. sshd reads values without
// regard to case and refuses to start on any other value.
var sshdValues = map[string][]string{
	keywordRootLogin:    {"yes", "prohibit-password", "without-password", "forced-commands-only", "no"},
	keywordPasswordAuth: {"yes", "no"},
}

// parseSSHDConfig reads the configuration in main, read from path, and every
// file it includes, resolving a relative Include against dir as sshd does. It
// follows sshd's rules: a keyword is matched without regard to case and may be
// joined to its value by an equals sign, a value may be quoted, the first value
// of a keyword is the one used, an included file is read in place with a glob
// expanded in lexical order, an Include that matches nothing is ignored, and a
// Match block, including one begun inside an included file, ends at the next
// Match line or at the end of the file it began in. On a read error what was
// read is returned with it: a value already found is the one sshd uses whatever
// follows, and one not yet found is unknown.
func parseSSHDConfig(main io.Reader, path, dir string) (sshConfig, error) {
	p := &sshdParser{
		dir:     dir,
		config:  sshConfig{global: map[string]sshSetting{}},
		reading: []string{filepath.Clean(path)},
	}
	err := p.read(main, path, -1)
	return p.config, err
}

// read parses one file's lines into block, the index of the Match block the
// file was included from, or -1 for the global section.
func (p *sshdParser) read(file io.Reader, path string, block int) error {
	scanner := bufio.NewScanner(file)
	for line := 1; scanner.Scan(); line++ {
		keyword, args, err := splitSSHDLine(scanner.Text())
		if err != nil {
			return fmt.Errorf("%s line %d: %w", path, line, err)
		}
		switch keyword {
		case "":
		case keywordMatch:
			if len(args) == 0 {
				return fmt.Errorf("%s line %d: Match names no criteria", path, line)
			}
			p.config.blocks = append(p.config.blocks, sshMatchBlock{criteria: strings.Join(args, " "), settings: map[string]sshSetting{}})
			block = len(p.config.blocks) - 1
		case keywordInclude:
			if err := p.include(args, block); err != nil {
				return fmt.Errorf("%s line %d: %w", path, line, err)
			}
		default:
			if _, judged := sshdValues[keyword]; judged {
				p.set(block, keyword, directiveSetting(keyword, args))
			}
		}
	}
	return scanner.Err()
}

// set records a keyword's setting unless the section already has one: sshd
// uses the first value it obtains.
func (p *sshdParser) set(block int, keyword string, setting sshSetting) {
	settings := p.config.global
	if block >= 0 {
		settings = p.config.blocks[block].settings
	}
	if _, ok := settings[keyword]; !ok {
		settings[keyword] = setting
	}
}

// include reads every file an Include names, in place. A pattern is expanded
// and its matches read in lexical order, and one that matches nothing is
// skipped, as sshd skips it. A file that is matched but cannot be read is an
// error, because what it sets is unknown.
func (p *sshdParser) include(patterns []string, block int) error {
	if len(patterns) == 0 {
		return errors.New("no file follows the Include keyword")
	}
	for _, pattern := range patterns {
		matches, err := filepath.Glob(includePath(p.dir, pattern))
		if err != nil {
			return fmt.Errorf("included pattern %s: %w", pattern, err)
		}
		slices.Sort(matches)
		for _, match := range matches {
			if err := p.includeFile(filepath.Clean(match), block); err != nil {
				return err
			}
		}
	}
	return nil
}

// includeFile reads one included file. A file already being read would be
// read again without end, which sshd also refuses.
func (p *sshdParser) includeFile(path string, block int) error {
	if slices.Contains(p.reading, path) {
		return fmt.Errorf("including %s leads back to a file already being read", path)
	}
	file, err := os.Open(path) // #nosec G304 -- an Include the sshd configuration names, read as sshd reads it
	if err != nil {
		return fmt.Errorf("cannot read included %s: %w", path, err)
	}
	defer file.Close() //nolint:errcheck // read-only file; close error does not affect scan results

	p.reading = append(p.reading, path)
	defer func() { p.reading = p.reading[:len(p.reading)-1] }()
	return p.read(file, path, block)
}

// includePath resolves an Include pattern as sshd does: a pattern beginning
// with a slash is absolute, and any other is relative to dir, the directory
// holding the main configuration. Windows sshd follows the same rule, so a
// pattern beginning with a drive letter is joined to dir there and matches
// nothing, and a leading slash names a path on dir's drive.
func includePath(dir, pattern string) string {
	if strings.HasPrefix(pattern, "/") {
		return filepath.FromSlash(filepath.VolumeName(dir) + pattern)
	}
	return filepath.Join(dir, pattern)
}

// directiveSetting is the setting a judged directive's arguments make, or the
// reason sshd refuses them.
func directiveSetting(keyword string, args []string) sshSetting {
	switch {
	case len(args) == 0:
		return sshSetting{found: true, rejected: "no value is given"}
	case len(args) > 1:
		return sshSetting{value: strings.Join(args, " "), found: true, rejected: "more than one value is given"}
	case !slices.Contains(sshdValues[keyword], strings.ToLower(args[0])):
		return sshSetting{value: args[0], found: true, rejected: "the value is not one sshd accepts"}
	default:
		return sshSetting{value: args[0], found: true}
	}
}

// splitSSHDLine splits one configuration line as sshd does: the keyword, in
// lower case, ends at white space or an equals sign, one equals sign may sit
// between it and the arguments, an argument may be double-quoted, and a word
// beginning with # ends the line. A blank line or comment has no keyword.
func splitSSHDLine(line string) (keyword string, args []string, err error) {
	line = strings.TrimLeft(line, " \t")
	if line == "" || line[0] == '#' {
		return "", nil, nil
	}
	end := strings.IndexAny(line, " \t=")
	if end < 0 {
		return strings.ToLower(line), nil, nil
	}
	keyword = strings.ToLower(line[:end])
	rest := strings.TrimLeft(line[end:], " \t")
	rest = strings.TrimLeft(strings.TrimPrefix(rest, "="), " \t")

	for rest != "" && rest[0] != '#' {
		var arg string
		if rest[0] == '"' {
			closing := strings.IndexByte(rest[1:], '"')
			if closing < 0 {
				return keyword, nil, errors.New("a quoted value is not closed")
			}
			arg, rest = rest[1:closing+1], rest[closing+2:]
			if arg == "" {
				return keyword, nil, errors.New("a quoted value is empty")
			}
		} else {
			stop := strings.IndexAny(rest, " \t")
			if stop < 0 {
				stop = len(rest)
			}
			arg, rest = rest[:stop], rest[stop:]
		}
		args = append(args, arg)
		rest = strings.TrimLeft(rest, " \t")
	}
	return keyword, args, nil
}

// checkSSHDConfig reads the OpenSSH server configuration at path, with every
// file it includes, and concludes the rules its directives decide. It opens
// the file directly rather than stat-then-open: the two-call form leaves a
// window in which the file can change between the check and the use, and one
// error already distinguishes absent from unreadable. An absent file fails its
// own rule and leaves the directive rules unchecked; an unreadable one is an
// error on all of them.
func checkSSHDConfig(r *report, path string, absent sshdAbsentKeys) {
	directives := []registry.FindingKey{
		"ssh.root_login_permitted", "ssh.password_auth_enabled",
		absent.rootLogin, absent.passwordAuth,
	}

	file, err := os.Open(path) // #nosec G304 -- path is a platform constant naming the sshd configuration
	switch {
	case errors.Is(err, os.ErrNotExist):
		r.observed("ssh.config_not_found", evidence(finding.KindFile, path))
		r.inconclusive(finding.ResultNotChecked, "OpenSSH configuration file not found: "+path, directives...)
		return
	case err != nil:
		r.inconclusive(finding.ResultError, fmt.Sprintf("cannot read OpenSSH configuration: %v", err),
			append(directives, "ssh.config_not_found")...)
		return
	}
	defer file.Close() //nolint:errcheck // read-only file; close error does not affect scan results

	r.pass("ssh.config_not_found")
	r.note(finding.SymbolInfo, "Configuration file: %s", path)

	config, readErr := parseSSHDConfig(file, path, filepath.Dir(path))

	reportSSHDirective(r, config, readErr, keywordRootLogin, sshRule{
		name:      "PermitRootLogin",
		unsafe:    func(value string) bool { return !strings.EqualFold(value, "no") },
		unsafeKey: "ssh.root_login_permitted",
		absentKey: absent.rootLogin,
	})

	reportSSHDirective(r, config, readErr, keywordPasswordAuth, sshRule{
		name:      "PasswordAuthentication",
		unsafe:    func(value string) bool { return strings.EqualFold(value, "yes") },
		unsafeKey: "ssh.password_auth_enabled",
		absentKey: absent.passwordAuth,
	})
}

// reportSSHDirective concludes the rules one directive decides, from its global
// setting and from each Match block that sets it. An absent directive is a
// third condition rather than a variant of either value, because sshd applies
// its own default to what the configuration does not say, and that default is
// not visible in the configuration being audited. A directive not found in a
// configuration that could not be read to the end is an error rather than an
// absence: the part that was not read may have set it. A value sshd refuses
// is not judged, because the server does not start with it. A Match block that
// sets an unsafe value fails the rule for the connections it matches, whatever
// the global setting, and its criteria are recorded with the value.
func reportSSHDirective(r *report, config sshConfig, readErr error, keyword string, rule sshRule) {
	global := config.global[keyword]
	switch {
	case !global.found && readErr != nil:
		r.inconclusive(finding.ResultError,
			fmt.Sprintf("OpenSSH configuration could not be read in full: %v", readErr),
			rule.unsafeKey, rule.absentKey)
	case !global.found:
		r.inconclusive(finding.ResultNotChecked,
			rule.name+" is not set; the sshd default applies and is not read", rule.unsafeKey)
		if rule.absentKey != "" {
			r.observed(rule.absentKey, evidence(finding.KindDirective, rule.name, fact(finding.FactState, "not set")))
		}
	case global.rejected != "":
		r.inconclusive(finding.ResultUnknown, rejectedReason(rule.name, global), rule.unsafeKey)
		r.pass(rule.absentKey)
	case rule.unsafe(global.value):
		r.observed(rule.unsafeKey, evidence(finding.KindDirective, rule.name, fact(finding.FactValue, global.value)))
		r.pass(rule.absentKey)
	default:
		r.pass(rule.unsafeKey, rule.absentKey)
	}

	for _, block := range config.blocks {
		setting, ok := block.settings[keyword]
		switch {
		case !ok:
		case setting.rejected != "":
			r.inconclusive(finding.ResultUnknown, rejectedReason(rule.name, setting)+" (Match "+block.criteria+")", rule.unsafeKey)
		case rule.unsafe(setting.value):
			r.observed(rule.unsafeKey, evidence(finding.KindDirective, rule.name,
				fact(finding.FactValue, setting.value), fact(finding.FactMatch, block.criteria)))
		}
	}
}

// rejectedReason states that sshd refuses a directive's setting and why.
func rejectedReason(name string, setting sshSetting) string {
	return fmt.Sprintf("sshd refuses %s %q: %s, so the server does not start with this configuration", name, setting.value, setting.rejected)
}
