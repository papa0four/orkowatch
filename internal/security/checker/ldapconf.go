// internal/security/checker/ldapconf.go

package checker

import (
	"cmp"
	"fmt"
	"io/fs"
	"net"
	"slices"
	"strings"
)

// nslcdConfFile is where nslcd reads its configuration on every supported
// family, relative to the root of the file system read.
const nslcdConfFile = "etc/nslcd.conf"

// How a client reaches the server a URI names.
const (
	ldapUnrecognised ldapReach = iota
	ldapOverTLS
	ldapOnHost
	ldapInClear
)

var (
	// The values nslcd was seen to accept for a boolean option and for
	// start_tls, without regard to case. It does not start on any other.
	nslcdTrue     = []string{"on", "yes", "true", "1"}
	nslcdFalse    = []string{"off", "no", "false", "0"}
	nslcdStartTLS = []string{"start_tls", "starttls"}

	// nslcdReqcert holds the values nslcd was seen to accept for tls_reqcert,
	// and whether each lets a session go on with a certificate that does not
	// verify. It reads yes as demand and no as never.
	nslcdReqcert = map[string]bool{
		"never": true, "allow": true, "no": true,
		"try": false, "demand": false, "hard": false, "yes": false,
	}

	// ldapReqcert holds the values the OpenLDAP library accepts for
	// TLS_REQCERT (ldap.conf(5)), and whether each lets a session go on with
	// a certificate that does not verify. It ignores a line with any other.
	ldapReqcert = map[string]bool{
		"never": true, "allow": true,
		"try": false, "demand": false, "hard": false,
	}
)

type (
	// ldapReach is how a client reaches a directory server.
	ldapReach int

	// ldapSetting is one option as nslcd.conf or ldap.conf states it.
	ldapSetting struct {
		value string
		line  int
	}

	// ldapOptions holds every setting of each option of one file, under the
	// option's name in lower case, in the order written.
	ldapOptions map[string][]ldapSetting

	// nslcdConfig is nslcd.conf as nslcd reads it. refused says why nslcd
	// does not start with the file, as far as the options judged show: an
	// unknown keyword also stops it, and which keywords it knows differs by
	// release, so that is not read.
	nslcdConfig struct {
		options ldapOptions
		refused []string
	}
)

// readLDAPOptions reads the lines of an nslcd.conf or an ldap.conf, which
// share a syntax: an option name, white space, and its value, with the name
// read without regard to case. A line beginning with # is a comment; one that
// begins with blanks and then # is not, to either program.
func readLDAPOptions(data []byte) ldapOptions {
	options := ldapOptions{}
	for i, raw := range strings.Split(string(data), "\n") {
		fields := strings.Fields(raw)
		if len(fields) == 0 || raw[0] == '#' {
			continue
		}
		name := strings.ToLower(fields[0])
		options[name] = append(options[name], ldapSetting{value: strings.Join(fields[1:], " "), line: i + 1})
	}
	return options
}

// last returns the last setting of an option, and whether the file sets it.
func (o ldapOptions) last(option string) (ldapSetting, bool) {
	settings := o[option]
	if len(settings) == 0 {
		return ldapSetting{}, false
	}
	return settings[len(settings)-1], true
}

// readNslcdConfig reads nslcd.conf and notes what nslcd refuses in it.
func readNslcdConfig(fsys fs.FS) (nslcdConfig, error) {
	data, err := fs.ReadFile(fsys, nslcdConfFile)
	if err != nil {
		return nslcdConfig{}, err
	}
	config := nslcdConfig{options: readLDAPOptions(data)}
	config.check()
	return config, nil
}

// check records each line of the options judged that nslcd was seen to
// refuse: a comment after blanks, which it reads as a keyword, an option
// without its value or with one too many, a value it does not accept, and a
// file naming no server.
func (c *nslcdConfig) check() {
	type refusal struct {
		line int
		text string
	}
	var refusals []refusal
	refuse := func(set ldapSetting, format string, args ...any) {
		refusals = append(refusals, refusal{set.line, lineRef("/"+nslcdConfFile, set.line) + " " + fmt.Sprintf(format, args...)})
	}

	single := map[string]func(string) bool{
		"ssl": func(value string) bool {
			return slices.Contains(slices.Concat(nslcdTrue, nslcdFalse, nslcdStartTLS), value)
		},
		"tls_reqcert": func(value string) bool { _, ok := nslcdReqcert[value]; return ok },
		"ignorecase":  func(value string) bool { return slices.Contains(slices.Concat(nslcdTrue, nslcdFalse), value) },
	}
	for name, settings := range c.options {
		accepts, judged := single[name]
		for _, set := range settings {
			switch {
			case strings.HasPrefix(name, "#"):
				refuse(set, "is a comment after blanks, which nslcd reads as a keyword")
			case name == "uri" && set.value == "":
				refuse(set, "names no server")
			case judged && len(strings.Fields(set.value)) != 1:
				refuse(set, "gives %s %d values where nslcd takes one", name, len(strings.Fields(set.value)))
			case judged && !accepts(strings.ToLower(set.value)):
				refuse(set, "sets %s to %q, which nslcd does not accept", name, set.value)
			}
		}
	}
	slices.SortFunc(refusals, func(a, b refusal) int { return cmp.Compare(a.line, b.line) })
	for _, r := range refusals {
		c.refused = append(c.refused, r.text)
	}
	if len(c.options["uri"]) == 0 {
		c.refused = append(c.refused, "/"+nslcdConfFile+" names no uri")
	}
}

// servers returns each server a uri line names, with the line it is on. A
// line may name several, and nslcd tries every one of every line.
func (c nslcdConfig) servers() []ldapSetting {
	var out []ldapSetting
	for _, set := range c.options["uri"] {
		for _, server := range strings.Fields(set.value) {
			out = append(out, ldapSetting{value: server, line: set.line})
		}
	}
	return out
}

// encrypted returns the ssl line that makes nslcd encrypt its connections to
// ldap:// servers, and whether there is one. It is the last line setting on
// or start_tls: nslcd was seen to keep it whatever a later off says.
func (c nslcdConfig) encrypted() (ldapSetting, bool) {
	settings := c.options["ssl"]
	for i := len(settings) - 1; i >= 0; i-- {
		if value := strings.ToLower(settings[i].value); slices.Contains(nslcdTrue, value) || slices.Contains(nslcdStartTLS, value) {
			return settings[i], true
		}
	}
	return ldapSetting{}, false
}

// nslcdReach is how nslcd reaches a server one uri argument names. DNS, alone
// or followed by a domain, has it look the servers up and was seen to give
// ldap:// ones. DNSLDAPS gives ldaps:// ones from the release whose
// nslcd.conf(5) lists it; an earlier release takes it as a server name it
// cannot reach, so neither sends anything in clear.
func nslcdReach(server string) ldapReach {
	name, _, _ := strings.Cut(strings.ToUpper(server), ":")
	switch name {
	case "DNS":
		return ldapInClear
	case "DNSLDAPS":
		return ldapOverTLS
	}
	return ldapReachOf(server)
}

// ldapReachOf is how a client of the OpenLDAP library reaches the server uri
// names: over TLS for ldaps, and for ldap in clear unless the client asks for
// TLS itself. An ldapi socket, a loopback address, localhost and an ldap URI
// with no host, which the library was seen to take as the host itself, do not
// leave the host. The scheme is read without regard to case, as the library
// reads it.
func ldapReachOf(uri string) ldapReach {
	scheme, rest, ok := strings.Cut(uri, "://")
	if !ok {
		return ldapUnrecognised
	}
	switch strings.ToLower(scheme) {
	case "ldaps":
		return ldapOverTLS
	case "ldapi":
		return ldapOnHost
	case "ldap":
	default:
		return ldapUnrecognised
	}

	host := rest
	if end := strings.IndexAny(host, "/?"); end >= 0 {
		host = host[:end]
	}
	if strings.HasPrefix(host, "[") {
		host, _, _ = strings.Cut(host[1:], "]")
	} else {
		host, _, _ = strings.Cut(host, ":")
	}
	if ip := net.ParseIP(host); host == "" || strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback() {
		return ldapOnHost
	}
	return ldapInClear
}
