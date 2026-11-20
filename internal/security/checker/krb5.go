// internal/security/checker/krb5.go

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

// The rules that judge the Kerberos client configuration, and the condition
// recording that one is present.
const (
	ruleKrb5Present    registry.FindingKey = "users.kerberos_configured"
	ruleKrb5Weak       registry.FindingKey = "users.krb5_weak_enctypes"
	ruleKrb5Deprecated registry.FindingKey = "users.krb5_deprecated_enctypes"
)

// krb5DefaultKeytab is the keytab the library on every supported family uses
// when default_keytab_name is not set. krb5VendorFile is the vendor copy of
// krb5.conf the library of some families reads. Both are relative to the root
// of the file system read.
const (
	krb5DefaultKeytab = "etc/krb5.keytab"
	krb5VendorFile    = "usr/etc/krb5.conf"
)

// The encryption types kdc.conf(5) lists, by the first name it gives each.
const (
	encDES3Raw     = "des3-cbc-raw"
	encDES3        = "des3-cbc-sha1"
	encAES256SHA1  = "aes256-cts-hmac-sha1-96"
	encAES128SHA1  = "aes128-cts-hmac-sha1-96"
	encAES256SHA2  = "aes256-cts-hmac-sha384-192"
	encAES128SHA2  = "aes128-cts-hmac-sha256-128"
	encRC4         = "arcfour-hmac"
	encRC4Export   = "arcfour-hmac-exp"
	encCamellia256 = "camellia256-cts-cmac"
	encCamellia128 = "camellia128-cts-cmac"
)

var (
	krb5Rules = []registry.FindingKey{ruleKrb5Weak, ruleKrb5Deprecated}

	// krb5Lists are the relations holding encryption type lists. The last two
	// take the value of the first when unset (krb5.conf(5), from release 1.18).
	krb5Lists = []string{"permitted_enctypes", "default_tkt_enctypes", "default_tgs_enctypes"}

	// krb5Names maps every name kdc.conf(5) accepts in a list to the types it
	// stands for: each type's own names, and the four families.
	krb5Names = map[string][]string{
		"des3-cbc-raw":  {encDES3Raw},
		"des3-cbc-sha1": {encDES3}, "des3-hmac-sha1": {encDES3}, "des3-cbc-sha1-kd": {encDES3},
		"aes256-cts-hmac-sha1-96": {encAES256SHA1}, "aes256-cts": {encAES256SHA1}, "aes256-sha1": {encAES256SHA1},
		"aes128-cts-hmac-sha1-96": {encAES128SHA1}, "aes128-cts": {encAES128SHA1}, "aes128-sha1": {encAES128SHA1},
		"aes256-cts-hmac-sha384-192": {encAES256SHA2}, "aes256-sha2": {encAES256SHA2},
		"aes128-cts-hmac-sha256-128": {encAES128SHA2}, "aes128-sha2": {encAES128SHA2},
		"arcfour-hmac": {encRC4}, "rc4-hmac": {encRC4}, "arcfour-hmac-md5": {encRC4},
		"arcfour-hmac-exp": {encRC4Export}, "rc4-hmac-exp": {encRC4Export}, "arcfour-hmac-md5-exp": {encRC4Export},
		"camellia256-cts-cmac": {encCamellia256}, "camellia256-cts": {encCamellia256},
		"camellia128-cts-cmac": {encCamellia128}, "camellia128-cts": {encCamellia128},
		"des3":     {encDES3},
		"aes":      {encAES256SHA1, encAES128SHA1, encAES256SHA2, encAES128SHA2},
		"rc4":      {encRC4},
		"camellia": {encCamellia256, encCamellia128},
	}

	// The types kdc.conf(5) marks weak, and those it marks deprecated.
	krb5Weak       = []string{encDES3Raw, encRC4Export}
	krb5Deprecated = []string{encDES3, encRC4}
	krb5TripleDES  = []string{encDES3Raw, encDES3}

	// krb5DefaultTypes is what the library requests with no list set, in its
	// order, on the builds that have triple DES.
	krb5DefaultTypes = []string{
		encAES256SHA1, encAES128SHA1, encAES256SHA2, encAES128SHA2,
		encDES3, encRC4, encCamellia256, encCamellia128,
	}

	// krb5Builds are the builds whose default set was observed, from the
	// encryption types the library requests with nothing set. The Red Hat
	// builds request no triple DES type, named or not.
	krb5Builds = []krb5Build{
		{family: registry.DistroDebian, releases: []string{"1.19", "1.20"}, tripleDES: true},
		{family: registry.DistroSUSE, releases: []string{"1.20", "1.22"}, tripleDES: true},
		{family: registry.DistroArch, releases: []string{"1.22"}, tripleDES: true},
		{family: registry.DistroAlpine, releases: []string{"1.21"}, tripleDES: true},
		{family: registry.DistroRHEL, releases: []string{"1.21"}},
		{family: registry.DistroFedora, releases: []string{"1.21"}},
	}
)

type (
	// krb5Build is one distribution family's build of the library at the
	// releases it was observed at, and whether it has the triple DES types.
	krb5Build struct {
		family    registry.Distro
		releases  []string
		tripleDES bool
	}

	// krb5Host is what the Kerberos rules need from the host besides its
	// files: the release installed.
	krb5Host struct {
		release func() (programRelease, error)
	}

	// krb5List is one encryption type list in force: the types in it, and
	// whether they depend on the build's default set.
	krb5List struct {
		types    []string
		defaults bool
	}
)

// krb5ReadsVendorFile reports whether the library of a host of families
// reads the vendor copy of krb5.conf, as the SUSE family's and Alpine's were
// seen to.
func krb5ReadsVendorFile(families []registry.Distro) bool {
	return slices.Contains(families, registry.DistroSUSE) || slices.Contains(families, registry.DistroAlpine)
}

// recordKerberos judges the Kerberos client configuration of a host of
// families. With no configuration there is nothing to judge. A distribution
// installs the file with the libraries, so the rules apply only where the
// host is seen to use Kerberos: it holds a keytab, or SSSD serves a domain
// that authenticates with the krb5 provider. sssd and sssdErr are the SSSD
// configuration as readSSSDConfig returned it.
func recordKerberos(r *report, fsys fs.FS, families []registry.Distro, host krb5Host, sssd sssdConfig, sssdErr error) {
	files, err := krb5ConfigFiles(fsys, families)
	if err == nil && len(files) == 0 {
		r.inconclusive(finding.ResultNotChecked, "no Kerberos configuration file is present", krb5Rules...)
		return
	}
	var config krb5Config
	if err == nil {
		config, err = readKrb5Config(fsys, files)
	}
	if err != nil {
		r.inconclusive(finding.ResultError, fmt.Sprintf("the Kerberos configuration could not be read: %v", err), krb5Rules...)
		return
	}

	signals := krb5Use(fsys, config, sssd)
	recorded := signals
	if realm, ok := config.libdefaults["default_realm"]; ok {
		recorded = append(recorded, settingEvidence(krb5Subject("default_realm"), realm))
	}
	if len(recorded) > 0 {
		r.observed(ruleKrb5Present, recorded...)
	}
	switch {
	case len(signals) == 0 && sssdErr != nil && !errors.Is(sssdErr, fs.ErrNotExist):
		r.inconclusive(finding.ResultError, fmt.Sprintf(
			"the host has no keytab, and whether an SSSD domain authenticates with krb5 could not be read: %v", sssdErr), krb5Rules...)
		return
	case len(signals) == 0:
		r.inconclusive(finding.ResultNotApplicable,
			"the host is not seen to use Kerberos: it has no keytab, and SSSD serves no domain that authenticates with the krb5 provider",
			krb5Rules...)
		return
	case len(config.refused) > 0:
		r.inconclusive(finding.ResultUnknown,
			strings.Join(config.refused, "; ")+", so the library does not start with this configuration", krb5Rules...)
		return
	}

	release, releaseErr := host.release()
	if releaseErr != nil {
		r.note(finding.SymbolWarning, "The Kerberos release could not be read: %v", releaseErr)
	}
	krb5Judge{r: r, config: config, build: krb5BuildOf(families, release, releaseErr), release: release}.judge()
}

// krb5Use returns the evidence that the host uses Kerberos: its keytab, and
// each domain SSSD serves that authenticates with the krb5 provider.
func krb5Use(fsys fs.FS, config krb5Config, sssd sssdConfig) []finding.Evidence {
	var signals []finding.Evidence
	keytab := krb5DefaultKeytab
	if named, ok := config.libdefaults["default_keytab_name"]; ok {
		keytab = strings.TrimPrefix(strings.TrimPrefix(named.value, "FILE:"), "/")
	}
	if _, err := fs.Stat(fsys, keytab); err == nil {
		signals = append(signals, evidence(finding.KindFile, "/"+keytab, fact(finding.FactSource, "keytab")))
	}
	for _, domain := range sssd.domains() {
		if domain.auth != "krb5" {
			continue
		}
		provider, _ := sssd.get(domain.section, "auth_provider")
		signals = append(signals, settingEvidence("["+domain.section+"] auth_provider", provider))
	}
	return signals
}

// krb5Subject names a [libdefaults] relation as its evidence does.
func krb5Subject(relation string) string {
	return "[" + krb5Libdefaults + "] " + relation
}

// krb5BuildOf returns the observed build matching the host's most specific
// family and its release, or nil when the release is unknown or the build was
// not observed.
func krb5BuildOf(families []registry.Distro, release programRelease, releaseErr error) *krb5Build {
	if releaseErr != nil {
		return nil
	}
	series := release.series()
	for _, family := range families {
		for i, build := range krb5Builds {
			if build.family == family && slices.Contains(build.releases, series) {
				return &krb5Builds[i]
			}
		}
	}
	return nil
}

// krb5Judge concludes the two rules from the lists in force.
type krb5Judge struct {
	r       *report
	config  krb5Config
	build   *krb5Build
	release programRelease
}

// judge concludes both rules. A weak type is in force only where
// allow_weak_crypto is true: "If this flag is set to false, then weak
// encryption types ... will be filtered out of the lists" (krb5.conf(5)).
func (j krb5Judge) judge() {
	const flag = "allow_weak_crypto"
	allowWeak := false
	if set, ok := j.config.libdefaults[flag]; ok {
		value, known := krb5Bool(set.value)
		switch {
		case !known:
			j.r.inconclusive(finding.ResultUnknown, fmt.Sprintf(
				"%s is %q at %s, which the library refuses, so it does not start with this configuration",
				flag, set.value, set.at()), krb5Rules...)
			return
		case j.config.undecided[flag] != "":
			j.r.inconclusive(finding.ResultUnknown, j.config.undecided[flag], ruleKrb5Weak)
			j.deprecated()
			return
		}
		allowWeak = value
	}

	var weak []finding.Evidence
	for _, relation := range j.lists() {
		list, reason := j.list(relation)
		switch {
		case reason != "" && allowWeak:
			j.r.inconclusive(finding.ResultUnknown, reason, ruleKrb5Weak)
		case reason == "" && allowWeak:
			if found := intersect(list.types, krb5Weak); len(found) > 0 {
				weak = append(weak, j.listEvidence(relation, found))
			}
		}
	}
	if len(weak) > 0 {
		j.r.observed(ruleKrb5Weak, append([]finding.Evidence{settingEvidence(krb5Subject(flag), j.config.libdefaults[flag])}, weak...)...)
	} else {
		j.r.pass(ruleKrb5Weak)
	}
	j.deprecated()
}

// deprecated concludes the rule on the types kdc.conf(5) marks deprecated,
// which are "available for compatibility but not recommended for use".
func (j krb5Judge) deprecated() {
	var found []finding.Evidence
	for _, relation := range j.lists() {
		list, reason := j.list(relation)
		if reason != "" {
			j.r.inconclusive(finding.ResultUnknown, reason, ruleKrb5Deprecated)
			continue
		}
		if types := intersect(list.types, krb5Deprecated); len(types) > 0 {
			found = append(found, j.listEvidence(relation, types))
		}
	}
	if len(found) > 0 {
		j.r.observed(ruleKrb5Deprecated, found...)
		return
	}
	j.r.pass(ruleKrb5Deprecated)
}

// lists returns the relations to judge: permitted_enctypes, set or not, and
// each of the other two a file sets. One left unset takes the value of
// permitted_enctypes, so judging it would repeat that list.
func (j krb5Judge) lists() []string {
	out := []string{krb5Lists[0]}
	for _, relation := range krb5Lists[1:] {
		if _, ok := j.config.libdefaults[relation]; ok {
			out = append(out, relation)
		}
	}
	return out
}

// list returns the types in force for a relation, weak types included, or why
// they are not known. Names are read as kdc.conf(5) gives
// them and as the library was seen to: separated by commas or white space,
// without regard to case, DEFAULT for the build's default set, a leading minus
// removing what is named from the list so far, and a name the library does not
// know ignored. A build without triple DES requests none of its types.
func (j krb5Judge) list(relation string) (krb5List, string) {
	var list krb5List
	set, ok := j.config.libdefaults[relation]
	if reason := j.config.undecided[relation]; reason != "" {
		return list, reason
	}

	value := "DEFAULT"
	if ok {
		value = set.value
	}
	for _, name := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		name = strings.ToLower(name)
		remove := strings.HasPrefix(name, "-")
		name = strings.TrimLeft(name, "+-")
		types := krb5Names[name]
		if name == "default" {
			types, list.defaults = krb5DefaultTypes, true
		}
		for _, t := range types {
			switch {
			case remove:
				list.types = slices.DeleteFunc(list.types, func(have string) bool { return have == t })
			case !slices.Contains(list.types, t):
				list.types = append(list.types, t)
			}
		}
	}

	named := len(intersect(list.types, krb5TripleDES)) > 0
	switch {
	case j.build == nil && (list.defaults || named):
		return list, fmt.Sprintf(
			"%s depends on the default set or the triple DES types of this build of the library, which was not observed for this distribution and release",
			relation)
	case j.build != nil && !j.build.tripleDES:
		list.types = slices.DeleteFunc(list.types, func(t string) bool { return slices.Contains(krb5TripleDES, t) })
	}
	return list, ""
}

// listEvidence is the evidence of one list holding the types found: where its
// value is set, or that it is unset and the build's default applies.
func (j krb5Judge) listEvidence(relation string, found []string) finding.Evidence {
	inForce := fact(finding.FactDescription, "in force: "+strings.Join(found, ", "))
	if set, ok := j.config.libdefaults[relation]; ok {
		return settingEvidence(krb5Subject(relation), set, inForce)
	}
	return unsetEvidence(krb5Subject(relation), fact(finding.FactVersion, j.release.text), inForce)
}

// intersect returns the members of list that are in set, in list's order.
func intersect(list, set []string) []string {
	var out []string
	for _, item := range list {
		if slices.Contains(set, item) {
			out = append(out, item)
		}
	}
	return out
}
