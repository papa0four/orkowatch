// internal/security/checker/ldap.go

package checker

import (
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
)

// The rules that judge the nslcd and OpenLDAP client configurations, and the
// conditions recording that each is present.
const (
	ruleLDAPPresent      registry.FindingKey = "users.ldap_configured"
	ruleLDAPCertificate  registry.FindingKey = "users.ldap_cert_unchecked"
	ruleNslcdPresent     registry.FindingKey = "users.nslcd_configured"
	ruleNslcdLookups     registry.FindingKey = "users.nslcd_lookups_unencrypted"
	ruleNslcdLogins      registry.FindingKey = "users.nslcd_logins_unencrypted"
	ruleNslcdCertificate registry.FindingKey = "users.nslcd_cert_unchecked"
	ruleNslcdCase        registry.FindingKey = "users.nslcd_ignorecase"
	ruleNslcdReadable    registry.FindingKey = "users.nslcd_password_readable"
)

var (
	// nslcdUseRules are judged only where the host is wired to nslcd.
	nslcdUseRules = []registry.FindingKey{ruleNslcdLookups, ruleNslcdLogins, ruleNslcdCertificate, ruleNslcdCase}

	// nslcdPasswords are the options that hold a password (nslcd.conf(5)).
	nslcdPasswords = []string{"bindpw", "rootpwmodpw"}
)

// ldapEvidence is the evidence of one option of file as set, by the name the
// program's manual gives it.
func ldapEvidence(file, option string, set ldapSetting) finding.Evidence {
	return evidence(finding.KindSetting, option,
		fact(finding.FactValue, set.value), fact(finding.FactLine, lineRef(file, set.line)))
}

// recordNslcd judges /etc/nslcd.conf under fsys. Every distribution packages
// the file naming a server on the host itself, so what it sets is judged only
// where the host is wired to nslcd: lookups are the name service lines naming
// its service and logins the PAM rules naming its module. A password in the
// file is judged for who can read it whether or not nslcd is used.
func recordNslcd(r *report, fsys fs.FS, owner fileOwner, lookups, logins []finding.Evidence) {
	const file = "/" + nslcdConfFile
	all := append([]registry.FindingKey{ruleNslcdReadable}, nslcdUseRules...)
	config, err := readNslcdConfig(fsys)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		r.inconclusive(finding.ResultNotChecked, file+" is not present", all...)
		return
	case err != nil:
		r.inconclusive(finding.ResultError, fmt.Sprintf("%s could not be read: %v", file, err), all...)
		return
	}
	recordNslcdPassword(r, fsys, owner, config)

	switch {
	case len(lookups)+len(logins) == 0:
		r.inconclusive(finding.ResultNotApplicable,
			"the host is not seen to use nslcd: the name service switch does not name ldap, and no PAM rule names pam_ldap.so",
			nslcdUseRules...)
		return
	case len(config.refused) > 0:
		r.inconclusive(finding.ResultUnknown,
			strings.Join(config.refused, "; ")+", so nslcd does not start with this configuration", nslcdUseRules...)
		return
	}

	judge := nslcdJudge{r: r, config: config}
	for _, server := range config.servers() {
		switch nslcdReach(server.value) {
		case ldapInClear:
			judge.clear = append(judge.clear, ldapEvidence(file, "uri", server))
		case ldapOverTLS:
			judge.tls = append(judge.tls, ldapEvidence(file, "uri", server))
		case ldapUnrecognised:
			judge.unrecognised = append(judge.unrecognised, fmt.Sprintf("%s names %q", lineRef(file, server.line), server.value))
		}
	}
	judge.unencrypted(ruleNslcdLookups, lookups, "the name service switch does not name ldap")
	judge.unencrypted(ruleNslcdLogins, logins, "no PAM rule names pam_ldap.so")
	judge.certificate()
	judge.ignorecase()
}

// recordNslcdPassword judges who can read a password nslcd.conf holds.
// nslcd.conf(5), under bindpw and rootpwmodpw: "If you set this option you
// should consider changing the permissions of the nslcd.conf file to only
// grant access to the root user." The password is not recorded.
func recordNslcdPassword(r *report, fsys fs.FS, owner fileOwner, config nslcdConfig) {
	const file = "/" + nslcdConfFile
	var passwords []finding.Evidence
	for _, option := range nslcdPasswords {
		for _, set := range config.options[option] {
			if set.value != "" {
				passwords = append(passwords, evidence(finding.KindSetting, option, fact(finding.FactLine, lineRef(file, set.line))))
			}
		}
	}
	if len(passwords) == 0 {
		r.inconclusive(finding.ResultNotApplicable, file+" sets neither bindpw nor rootpwmodpw", ruleNslcdReadable)
		return
	}

	info, err := fs.Stat(fsys, nslcdConfFile)
	if err != nil {
		r.inconclusive(finding.ResultError, fmt.Sprintf("%s could not be checked: %v", file, err), ruleNslcdReadable)
		return
	}
	uid, gid, ok := owner(info)
	if !ok {
		r.inconclusive(finding.ResultError, file+" ownership could not be determined", ruleNslcdReadable)
		return
	}
	if read, _ := fileExcess(info.Mode().Perm(), uid, gid, localAccount{}); !read {
		r.pass(ruleNslcdReadable)
		return
	}
	r.observed(ruleNslcdReadable, append([]finding.Evidence{evidence(finding.KindFile, file,
		fact(finding.FactMode, formatMode(info.Mode())),
		fact(finding.FactUID, fmt.Sprint(uid)),
		fact(finding.FactGID, fmt.Sprint(gid)),
		fact(finding.FactExpected, "owned by root, with no access for its group or others"))}, passwords...)...)
}

// nslcdJudge concludes the rules that read what nslcd.conf sets. clear are
// the servers reached in clear unless ssl says otherwise, tls those reached
// over TLS whatever it says, and unrecognised the uri arguments that are
// neither a URI of the library nor a DNS lookup.
type nslcdJudge struct {
	r            *report
	config       nslcdConfig
	clear        []finding.Evidence
	tls          []finding.Evidence
	unrecognised []string
}

// unknown reports a rule unknown for the uri arguments that could not be
// read, and whether there were any.
func (j nslcdJudge) unknown(key registry.FindingKey) bool {
	if len(j.unrecognised) == 0 {
		return false
	}
	j.r.inconclusive(finding.ResultUnknown,
		strings.Join(j.unrecognised, "; ")+", which is not a server nslcd.conf(5) describes, so how nslcd connects is not known", key)
	return true
}

// unencrypted judges whether what wiring sends to nslcd crosses the network
// in clear: an ldap:// server off the host, or servers found in DNS, with no
// ssl line of on or start_tls. nslcd.conf(5): "Specifies whether to use
// SSL/TLS or not (the default is not to)". A rule with no wiring is not
// applicable, for the reason unwired gives.
func (j nslcdJudge) unencrypted(key registry.FindingKey, wiring []finding.Evidence, unwired string) {
	_, encrypted := j.config.encrypted()
	switch {
	case len(wiring) == 0:
		j.r.inconclusive(finding.ResultNotApplicable, unwired, key)
	case j.unknown(key):
	case encrypted || len(j.clear) == 0:
		j.r.pass(key)
	default:
		ssl := evidence(finding.KindSetting, "ssl", fact(finding.FactState, "not set"))
		if set, ok := j.config.options.last("ssl"); ok {
			ssl = ldapEvidence("/"+nslcdConfFile, "ssl", set)
		}
		j.r.observed(key, slices.Concat(wiring, []finding.Evidence{ssl}, j.clear)...)
	}
}

// certificate judges whether nslcd checks its server's certificate on the
// connections it encrypts: the last tls_reqcert is the one in force, and
// never and allow let a session go on with a certificate that does not verify
// (ldap.conf(5), to which nslcd.conf(5) refers for the values). nslcd does
// not take the setting from ldap.conf, and with none of its own it was seen
// to refuse such a certificate.
func (j nslcdJudge) certificate() {
	const file, option = "/" + nslcdConfFile, "tls_reqcert"
	reqcert, _ := j.config.options.last(option)
	via := j.tls
	if ssl, encrypted := j.config.encrypted(); encrypted {
		via = append([]finding.Evidence{ldapEvidence(file, "ssl", ssl)}, via...)
	}
	switch {
	case !nslcdReqcert[strings.ToLower(reqcert.value)]:
		j.r.pass(ruleNslcdCertificate)
	case j.unknown(ruleNslcdCertificate):
	case len(via) == 0:
		j.r.pass(ruleNslcdCertificate)
	default:
		j.r.observed(ruleNslcdCertificate, append([]finding.Evidence{ldapEvidence(file, option, reqcert)}, via...)...)
	}
}

// ignorecase judges whether nslcd matches names without regard to case: the
// last ignorecase line is the one in force, and it is off unless set.
// nslcd.conf(5): "Setting this to yes could open up the system to
// authorisation bypass vulnerabilities and introduce nscd cache poisoning
// vulnerabilities which allow denial of service."
func (j nslcdJudge) ignorecase() {
	const option = "ignorecase"
	if set, ok := j.config.options.last(option); ok && slices.Contains(nslcdTrue, strings.ToLower(set.value)) {
		j.r.observed(ruleNslcdCase, ldapEvidence("/"+nslcdConfFile, option, set))
		return
	}
	j.r.pass(ruleNslcdCase)
}

// recordOpenLDAP judges the OpenLDAP client library's configuration at path,
// which is empty where the distribution's path is not established. No
// distribution packages the file naming a server, so the library is seen to
// be used where the file sets URI or HOST. The last TLS_REQCERT the library
// accepts is the one in force, and it ignores a value it does not know.
// ldap.conf(5): with never "The client will not request or check any server
// certificate", with allow "If a bad certificate is provided, it will be
// ignored and the session proceeds normally", and demand "is the default
// setting".
func recordOpenLDAP(r *report, fsys fs.FS, path string) {
	if path == "" {
		r.inconclusive(finding.ResultNotChecked,
			"where the OpenLDAP client reads its configuration is not established for this distribution", ruleLDAPCertificate)
		return
	}
	data, err := fs.ReadFile(fsys, strings.TrimPrefix(path, "/"))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		r.inconclusive(finding.ResultNotChecked, path+" is not present", ruleLDAPCertificate)
		return
	case err != nil:
		r.inconclusive(finding.ResultError, fmt.Sprintf("%s could not be read: %v", path, err), ruleLDAPCertificate)
		return
	}

	options := readLDAPOptions(data)
	var servers []finding.Evidence
	for _, option := range []string{"uri", "host"} {
		for _, set := range options[option] {
			servers = append(servers, ldapEvidence(path, strings.ToUpper(option), set))
		}
	}
	if len(servers) == 0 {
		r.inconclusive(finding.ResultNotApplicable,
			"the OpenLDAP client is not seen to be used: "+path+" sets neither URI nor HOST", ruleLDAPCertificate)
		return
	}

	settings := options["tls_reqcert"]
	for i := len(settings) - 1; i >= 0; i-- {
		weak, accepted := ldapReqcert[strings.ToLower(settings[i].value)]
		switch {
		case !accepted:
			continue
		case weak:
			r.observed(ruleLDAPCertificate, append([]finding.Evidence{ldapEvidence(path, "TLS_REQCERT", settings[i])}, servers...)...)
		default:
			r.pass(ruleLDAPCertificate)
		}
		return
	}
	r.pass(ruleLDAPCertificate)
}
