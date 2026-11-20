// internal/security/checker/sssd.go

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

// The condition recording that SSSD is configured, and the rules that judge
// its configuration. The two file rules are judged whenever a file is
// present; the others need a domain SSSD serves.
const (
	ruleSSSDPresent     registry.FindingKey = "users.sssd_configured"
	ruleSSSDReadable    registry.FindingKey = "users.sssd_config_readable"
	ruleSSSDWritable    registry.FindingKey = "users.sssd_config_writable"
	ruleSSSDLDAPClear   registry.FindingKey = "users.sssd_ldap_id_unencrypted"
	ruleSSSDCertificate registry.FindingKey = "users.sssd_ldap_cert_unchecked"
	ruleSSSDCached      registry.FindingKey = "users.sssd_credentials_cached"
	ruleSSSDTicket      registry.FindingKey = "users.sssd_krb5_tgt_unvalidated"
)

// sssdAccountName is the user and group SSSD 2.10.0 and later runs as.
const sssdAccountName = "sssd"

var (
	sssdFileRules    = []registry.FindingKey{ruleSSSDReadable, ruleSSSDWritable}
	sssdContentRules = []registry.FindingKey{ruleSSSDLDAPClear, ruleSSSDCertificate, ruleSSSDCached, ruleSSSDTicket}

	// sssdForeignProviders are the providers whose own manuals set the
	// defaults of the LDAP and Kerberos options, so a domain using one is not
	// judged by the rules for the ldap and krb5 providers.
	sssdForeignProviders = []string{"ipa", "ad", "proxy"}
)

type (
	// sssdHost is what the SSSD rules need from the host besides its files:
	// the release installed, and who owns a file.
	sssdHost struct {
		version func() (programRelease, error)
		owner   fileOwner
	}

	// sssdDomain is one domain SSSD serves, with the providers it names.
	sssdDomain struct {
		name    string
		section string
		id      string
		auth    string
	}
)

// recordSSSD judges the SSSD configuration under fsys. With neither sssd.conf
// nor a snippet there is nothing to judge, whatever the name service switch or
// the PAM stack names. A file is judged for who can reach it whether or not
// SSSD is used; what it sets is judged only for the domains SSSD serves.
// config and err are the configuration as readSSSDConfig returned it.
func recordSSSD(r *report, fsys fs.FS, host sssdHost, config sssdConfig, err error) {
	all := slices.Concat(sssdFileRules, sssdContentRules)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		r.inconclusive(finding.ResultNotChecked,
			"neither /"+sssdConfFile+" nor a snippet in /"+sssdSnippetDir+" is present", all...)
		return
	case err != nil:
		r.inconclusive(finding.ResultError, fmt.Sprintf("the SSSD configuration could not be read: %v", err), all...)
		return
	}

	version, versionErr := host.version()
	if versionErr != nil {
		r.note(finding.SymbolWarning, "The SSSD release could not be read: %v", versionErr)
	}
	recordSSSDFiles(r, fsys, config, host, version, versionErr)

	if len(config.malformed) > 0 {
		r.inconclusive(finding.ResultUnknown,
			strings.Join(config.malformed, "; ")+", so what SSSD reads from the configuration is not known", sssdContentRules...)
		return
	}
	domains := config.domains()
	if len(domains) == 0 {
		r.inconclusive(finding.ResultNotApplicable,
			"SSSD serves no domain: none with a section is listed in domains in [sssd] or sets enabled = true", sssdContentRules...)
		return
	}
	for _, domain := range domains {
		r.observed(ruleSSSDPresent, evidence(finding.KindSetting, "["+domain.section+"]",
			fact(finding.FactState, "active")))
	}

	judge := sssdJudge{r: r, config: config, version: version, versionErr: versionErr}
	judge.rule(ruleSSSDLDAPClear, "no active domain takes its identities from the ldap provider", domains, judge.ldapClear)
	judge.rule(ruleSSSDCertificate, "no active domain uses the ldap provider", domains, judge.certificate)
	judge.rule(ruleSSSDCached, "", domains, judge.cached)
	judge.rule(ruleSSSDTicket, "no active domain authenticates with the krb5 provider", domains, judge.ticket)
}

// domains returns the domains SSSD serves with their providers. sssd.conf(5):
// the authentication provider defaults to the identity provider.
func (c sssdConfig) domains() []sssdDomain {
	var out []sssdDomain
	for _, name := range c.activeDomains() {
		domain := sssdDomain{name: name, section: "domain/" + name}
		if id, ok := c.get(domain.section, "id_provider"); ok {
			domain.id = strings.ToLower(id.value)
		}
		domain.auth = domain.id
		if auth, ok := c.get(domain.section, "auth_provider"); ok {
			domain.auth = strings.ToLower(auth.value)
		}
		out = append(out, domain)
	}
	return out
}

// foreign reports whether d uses a provider the ldap and krb5 rules do not
// cover.
func (d sssdDomain) foreign() bool {
	return slices.Contains(sssdForeignProviders, d.id) || slices.Contains(sssdForeignProviders, d.auth)
}

// recordSSSDFiles judges who can reach sssd.conf and each snippet. Before
// SSSD 2.10.0 the manual requires each to be "owned by root and only root may
// read from or write to the file"; from 2.10.0 it "must be a regular file that
// is accessible only by the user used to run SSSD service or root"
// (sssd.conf(5)), and that user is sssd. With the release unknown, a file is
// judged only where both readings agree.
func recordSSSDFiles(r *report, fsys fs.FS, config sssdConfig, host sssdHost, version programRelease, versionErr error) {
	service := lookupLocalAccount(fsys, sssdAccountName)
	for _, name := range config.files {
		file, unread := statOwned(fsys, name, host.owner)
		if unread != "" {
			r.inconclusive(finding.ResultError, unread, sssdFileRules...)
			continue
		}

		rootRead, rootWrite := file.excess(localAccount{})
		userRead, userWrite := file.excess(service)
		conclude := func(key registry.FindingKey, root, user bool) {
			excess, expected := root, expectRootOnly
			switch {
			case versionErr != nil && root != user:
				r.inconclusive(finding.ResultUnknown, fmt.Sprintf(
					"%s is %s owned by %d:%d, which SSSD 2.10.0 and later allows and earlier releases do not, and the release could not be read",
					file.path, formatMode(file.mode), file.uid, file.gid), key)
				return
			case versionErr == nil && sssdRunsAsServiceUser(version):
				excess = user
				expected = "owned by root or sssd, with access for the sssd group at most and none for others"
			}
			if excess {
				r.observed(key, file.evidence(expected, fact(finding.FactVersion, version.text)))
				return
			}
			r.pass(key)
		}
		conclude(ruleSSSDReadable, rootRead, userRead)
		conclude(ruleSSSDWritable, rootWrite, userWrite)
	}
}

// sssdJudge concludes the rules that read what the configuration sets.
type sssdJudge struct {
	r          *report
	config     sssdConfig
	version    programRelease
	versionErr error
}

// rule concludes key from every domain it covers, and reports it not
// applicable, for the reason given, when it covers none. covers reports
// whether the rule applies to a domain and concludes it when it does.
func (j sssdJudge) rule(key registry.FindingKey, uncovered string, domains []sssdDomain, covers func(sssdDomain) bool) {
	var covered bool
	for _, domain := range domains {
		if covers(domain) {
			covered = true
		}
	}
	if !covered {
		j.r.inconclusive(finding.ResultNotApplicable, uncovered, key)
	}
}

// setting is the evidence of one option of a section: its value and where it
// is set, or that no file sets it.
func (j sssdJudge) setting(section, key string) finding.Evidence {
	subject := "[" + section + "] " + key
	set, ok := j.config.get(section, key)
	if !ok {
		return unsetEvidence(subject)
	}
	return settingEvidence(subject, set)
}

// boolean reads a boolean option of a section. known is false when the value
// is not one the manual gives or the locale decides which snippet sets it, and
// reason then says which.
func (j sssdJudge) boolean(section, key string, unset bool) (value, known bool, reason string) {
	set, ok := j.config.get(section, key)
	switch {
	case !ok:
		return unset, true, ""
	case j.config.undecided(section, key):
		return false, false, j.undecided(section, key)
	}
	value, known = sssdBool(set.value)
	if !known {
		reason = fmt.Sprintf("[%s] %s is %q at %s, which is neither true nor false", section, key, set.value, set.at())
	}
	return value, known, reason
}

// undecided says that the snippets setting an option differ and their order
// depends on the locale.
func (j sssdJudge) undecided(section, key string) string {
	return fmt.Sprintf("[%s] %s is set differently by snippets whose order depends on the locale SSSD runs in", section, key)
}

// ldapClear judges whether a domain's identity lookups reach an LDAP server
// unencrypted: a server named ldap:// with ldap_id_use_start_tls false, which
// is the default before SSSD 2.10.0 (sssd-ldap(5)). A server on the host
// itself is not counted. With no server named SSSD discovers them, and with a
// SASL mechanism the security layer it negotiates may protect the connection;
// neither is read from this configuration.
func (j sssdJudge) ldapClear(d sssdDomain) bool {
	if d.id != "ldap" || d.foreign() {
		return false
	}
	const key = "ldap_id_use_start_tls"
	if _, set := j.config.get(d.section, key); !set && j.versionErr != nil {
		j.r.inconclusive(finding.ResultUnknown, fmt.Sprintf(
			"[%s] %s is not set, its default is false before SSSD 2.10.0 and true from it, and the release could not be read",
			d.section, key), ruleSSSDLDAPClear)
		return true
	}
	startTLS, known, reason := j.boolean(d.section, key, sssdRunsAsServiceUser(j.version))
	switch {
	case !known:
		j.r.inconclusive(finding.ResultUnknown, reason, ruleSSSDLDAPClear)
		return true
	case startTLS:
		j.r.pass(ruleSSSDLDAPClear)
		return true
	}

	var servers []string
	var inClear bool
	for _, option := range []string{"ldap_uri", "ldap_backup_uri"} {
		if j.config.undecided(d.section, option) {
			j.r.inconclusive(finding.ResultUnknown, j.undecided(d.section, option), ruleSSSDLDAPClear)
			return true
		}
		set, _ := j.config.get(d.section, option)
		for _, uri := range strings.Split(set.value, ",") {
			if uri = strings.TrimSpace(uri); uri != "" {
				servers = append(servers, uri)
				inClear = inClear || ldapReachOf(uri) == ldapInClear
			}
		}
	}
	_, sasl := j.config.get(d.section, "ldap_sasl_mech")
	switch {
	case len(servers) == 0:
		j.r.inconclusive(finding.ResultUnknown, fmt.Sprintf(
			"[%s] names no ldap_uri, so SSSD discovers its servers and how it connects to them is not in the configuration", d.section),
			ruleSSSDLDAPClear)
	case !inClear:
		j.r.pass(ruleSSSDLDAPClear)
	case sasl:
		j.r.inconclusive(finding.ResultUnknown, fmt.Sprintf(
			"[%s] sets ldap_sasl_mech, and whether the SASL security layer protects its ldap:// connection is not in the configuration", d.section),
			ruleSSSDLDAPClear)
	default:
		use := j.setting(d.section, key)
		use.Facts = append(use.Facts, fact(finding.FactVersion, j.version.text))
		j.r.observed(ruleSSSDLDAPClear, use, j.setting(d.section, "ldap_uri"), j.setting(d.section, "ldap_backup_uri"))
	}
	return true
}

// certificate judges whether a domain checks its LDAP server's certificate:
// ldap_tls_reqcert of never or allow lets a session proceed with none or a bad
// one, and the default is hard (sssd-ldap(5)). The values are those of the
// OpenLDAP library's TLS_REQCERT.
func (j sssdJudge) certificate(d sssdDomain) bool {
	if d.id != "ldap" && d.auth != "ldap" || d.foreign() {
		return false
	}
	const key = "ldap_tls_reqcert"
	set, ok := j.config.get(d.section, key)
	unchecked, accepted := ldapReqcert[strings.ToLower(set.value)]
	switch {
	case !ok:
		j.r.pass(ruleSSSDCertificate)
	case j.config.undecided(d.section, key):
		j.r.inconclusive(finding.ResultUnknown, j.undecided(d.section, key), ruleSSSDCertificate)
	case !accepted:
		j.r.inconclusive(finding.ResultUnknown, fmt.Sprintf(
			"[%s] %s is %q at %s, which is not a value sssd-ldap(5) gives", d.section, key, set.value, set.at()),
			ruleSSSDCertificate)
	case unchecked:
		j.r.observed(ruleSSSDCertificate, j.setting(d.section, key))
	default:
		j.r.pass(ruleSSSDCertificate)
	}
	return true
}

// cached judges whether a domain keeps password hashes on the host:
// cache_credentials, which is false unless set (sssd.conf(5)). How long a
// cached login is allowed is recorded beside it and not judged.
func (j sssdJudge) cached(d sssdDomain) bool {
	const key = "cache_credentials"
	cached, known, reason := j.boolean(d.section, key, false)
	switch {
	case !known:
		j.r.inconclusive(finding.ResultUnknown, reason, ruleSSSDCached)
	case cached:
		j.r.observed(ruleSSSDCached, j.setting(d.section, key), j.setting("pam", "offline_credentials_expiration"))
	default:
		j.r.pass(ruleSSSDCached)
	}
	return true
}

// ticket judges whether a domain that authenticates with Kerberos verifies
// the ticket it is given: krb5_validate, which is false unless set for the
// krb5 provider (sssd-krb5(5)).
func (j sssdJudge) ticket(d sssdDomain) bool {
	if d.auth != "krb5" || d.foreign() {
		return false
	}
	const key = "krb5_validate"
	validated, known, reason := j.boolean(d.section, key, false)
	switch {
	case !known:
		j.r.inconclusive(finding.ResultUnknown, reason, ruleSSSDTicket)
	case validated:
		j.r.pass(ruleSSSDTicket)
	default:
		j.r.observed(ruleSSSDTicket, j.setting(d.section, key))
	}
	return true
}
