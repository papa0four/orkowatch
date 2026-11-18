// internal/security/checker/directory.go

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

type (
	// directoryClient is a program through which a Linux host can look up or
	// authenticate accounts against a directory: the rule recording it, the
	// file that configures it, empty where the host's distribution has no
	// established path, and the name service and PAM module that wire the
	// host's lookups and logins to it, empty where it provides none.
	directoryClient struct {
		label  string
		key    registry.FindingKey
		path   string
		nss    string
		module string
	}

	// nssWiring is the host's name service switch: where it was read and the
	// lines configuring the account databases.
	nssWiring struct {
		path  string
		lines []nssLine
	}
)

// nssDatabases are the name service databases that hold accounts and groups,
// with the pseudo-databases from which the compat service takes its entries
// (nsswitch.conf(5)).
var nssDatabases = []string{
	"passwd", "group", "shadow", "initgroups", "netgroup",
	"passwd_compat", "group_compat", "shadow_compat",
}

// directoryClients are the clients looked for on a host of families. The
// OpenLDAP client's path is the one compiled into each family's libldap:
// /etc/ldap/ldap.conf on the Debian family and /etc/openldap/ldap.conf on the
// others. The ldap name service and pam_ldap.so are nslcd's: on every family
// they come from nss-pam-ldapd, whose modules ask nslcd.
func directoryClients(families []registry.Distro) []directoryClient {
	return []directoryClient{
		{label: "OpenLDAP client", key: "users.ldap_configured", path: openLDAPConfig(families)},
		{label: "nslcd", key: "users.nslcd_configured", path: "/etc/nslcd.conf", nss: "ldap", module: "pam_ldap.so"},
		{label: "Kerberos", key: "users.kerberos_configured", path: "/etc/krb5.conf", module: "pam_krb5.so"},
		{label: "SSSD", key: "users.sssd_configured", path: "/etc/sssd/sssd.conf", nss: "sss", module: "pam_sss.so"},
	}
}

// openLDAPConfig returns where the OpenLDAP client library of the most
// specific recognised family reads its configuration, or empty when no family
// is recognised.
func openLDAPConfig(families []registry.Distro) string {
	for _, family := range families {
		switch family {
		case registry.DistroDebian:
			return "/etc/ldap/ldap.conf"
		case registry.DistroRHEL, registry.DistroFedora, registry.DistroArch, registry.DistroSUSE, registry.DistroAlpine:
			return "/etc/openldap/ldap.conf"
		}
	}
	return ""
}

// clientModules are the PAM modules of the directory clients.
func clientModules(clients []directoryClient) []string {
	var modules []string
	for _, client := range clients {
		if client.module != "" {
			modules = append(modules, client.module)
		}
	}
	return modules
}

// pamLayoutFor is where libpam takes its configuration on a host of families:
// /etc/pam.d, then /usr/lib/pam.d, then the vendor directory, which openSUSE
// builds as /usr/etc (PAM(8)); /etc/pam.conf when none exists. Debian's
// @include is in the Debian family's libpam alone.
func pamLayoutFor(families []registry.Distro) pamLayout {
	return pamLayout{
		dirs:      []string{"etc/pam.d", "usr/lib/pam.d", "usr/etc/pam.d"},
		conf:      "etc/pam.conf",
		atInclude: slices.Contains(families, registry.DistroDebian),
	}
}

// readNSSWiring reads the name service switch from /etc/nsswitch.conf, or
// from /usr/etc/nsswitch.conf where the first is absent, which is where
// openSUSE's glibc then reads it. Alpine's C library has no name service
// switch, as its own nsswitch.conf states, so nothing is read there.
func readNSSWiring(fsys fs.FS, families []registry.Distro) (nssWiring, []string) {
	if slices.Contains(families, registry.DistroAlpine) {
		return nssWiring{}, nil
	}
	for _, name := range []string{"etc/nsswitch.conf", "usr/etc/nsswitch.conf"} {
		data, err := fs.ReadFile(fsys, name)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return nssWiring{}, []string{fmt.Sprintf("/%s could not be read: %v", name, err)}
		}
		return nssWiring{path: "/" + name, lines: readNSSwitch(data, nssDatabases)}, nil
	}
	return nssWiring{}, nil
}

// recordDirectoryClients records, for each client, its configuration file
// and what the host wires to it. Both are informational: being configured or
// wired does not show the client is used. A client with neither records why.
// A file whose presence cannot be determined is an error, because the
// directory holding sssd.conf is unreadable to an unprivileged caller and a
// stat failure there is not evidence of absence.
func recordDirectoryClients(r *report, fsys fs.FS, clients []directoryClient, nss nssWiring, stack *pamStack) {
	for _, client := range clients {
		if client.path == "" {
			r.inconclusive(finding.ResultNotChecked,
				"where the "+client.label+" reads its configuration is not established for this distribution", client.key)
			continue
		}
		var subjects []finding.Evidence
		_, err := fs.Stat(fsys, strings.TrimPrefix(client.path, "/"))
		switch {
		case err == nil:
			subjects = append(subjects, evidence(finding.KindFile, client.path, fact(finding.FactSource, client.label)))
		case !errors.Is(err, fs.ErrNotExist):
			r.inconclusive(finding.ResultError,
				fmt.Sprintf("%s configuration could not be checked: %v", client.label, err), client.key)
			continue
		}
		subjects = append(subjects, client.wiring(nss, stack)...)
		if len(subjects) == 0 {
			r.inconclusive(finding.ResultInformational, client.absent(), client.key)
			continue
		}
		r.observed(client.key, subjects...)
	}
}

// wiring returns the name service lines and PAM rules naming the client.
func (c directoryClient) wiring(nss nssWiring, stack *pamStack) []finding.Evidence {
	var out []finding.Evidence
	if c.nss != "" {
		for _, line := range nss.lines {
			if slices.Contains(line.services, c.nss) {
				out = append(out, evidence(finding.KindNSSEntry, line.database,
					fact(finding.FactLine, lineRef(nss.path, line.line)), fact(finding.FactValue, line.value)))
			}
		}
	}
	if c.module != "" {
		for _, rule := range stack.wiring(c.module) {
			out = append(out, evidence(finding.KindPAMRule, rule.subject,
				fact(finding.FactLine, rule.line), fact(finding.FactServices, rule.services)))
		}
	}
	return out
}

// absent says that neither the client's file nor any wiring to it was found.
func (c directoryClient) absent() string {
	var names []string
	if c.nss != "" {
		names = append(names, "the name service switch does not name "+c.nss)
	}
	if c.module != "" {
		names = append(names, "no PAM rule names "+c.module)
	}
	reason := c.path + " is not present"
	for i, name := range names {
		if i == len(names)-1 {
			reason += ", and " + name
		} else {
			reason += ", " + name
		}
	}
	return reason
}
