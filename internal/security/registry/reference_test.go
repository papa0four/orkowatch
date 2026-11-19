// internal/security/registry/reference_test.go

package registry

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// allDefinitions returns every shipped definition under a label naming where
// it came from.
func allDefinitions() map[string]FindingDefinition {
	out := make(map[string]FindingDefinition)
	for platform, defs := range registry {
		for key, d := range defs {
			out[string(platform)+"/"+string(key)] = d
		}
	}
	for family, defs := range linuxRegistry {
		for key, d := range defs {
			out["linux/"+string(family)+"/"+string(key)] = d
		}
	}
	for family, defs := range unixRegistry {
		for key, d := range defs {
			out["unix/"+string(family)+"/"+string(key)] = d
		}
	}
	return out
}

// No reference a report can carry is one that was not verified.
func TestUnverifiedReferencesAreWithheld(t *testing.T) {
	var withheld, shown int
	for label, d := range allDefinitions() {
		for _, spec := range d.References {
			if spec.Source == RefTypeNIST || spec.Verified != "" {
				shown++
				continue
			}
			withheld++
			if _, ok := spec.report(); ok {
				t.Errorf("%s: unverified %s reference %q is reported", label, spec.Source, spec.ID)
			}
		}
		for _, ref := range d.ToReferences() {
			if ref.Type == RefTypeCIS {
				t.Errorf("%s: a CIS reference is reported while none is verified: %s", label, ref.Title)
			}
		}
	}
	if withheld == 0 || shown == 0 {
		t.Fatalf("expected both verified and withheld references, got %d shown and %d withheld", shown, withheld)
	}
}

// Every NIST citation resolves against the bundled catalog and is shown with
// NIST's title and the catalog's release; none states either itself.
func TestNISTReferencesResolveAgainstCatalog(t *testing.T) {
	if len(nist.Controls) < 1000 {
		t.Fatalf("the bundled catalog holds %d controls", len(nist.Controls))
	}
	for label, d := range allDefinitions() {
		for _, spec := range d.References {
			if spec.Source != RefTypeNIST {
				continue
			}
			title, ok := nist.Controls[spec.ID]
			if !ok {
				t.Errorf("%s cites %s, which is not in the catalog", label, spec.ID)
				continue
			}
			ref, shown := spec.report()
			want := "NIST " + nist.Release + " " + spec.ID + " (" + title + ")"
			if !shown || ref.Title != want {
				t.Errorf("%s: %s is shown as %q, want %q", label, spec.ID, ref.Title, want)
			}
		}
	}
}

// The citations added with this audit reach the finding a checker builds from
// the definition, looked up the way a checker looks it up for the host it ran on.
func TestAuditedReferencesReachFindings(t *testing.T) {
	const (
		rhelSELinux = "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/changing-selinux-states-and-modes_using-selinux#changing-to-enforcing-mode_changing-selinux-states-and-modes"
		rhelSudo    = "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_basic_system_settings/managing-sudo-access_configuring-basic-system-settings"
		msSSH       = "https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration"
	)
	windows := OSContext{Platform: PlatformWindows}
	rhel := OSContext{Platform: PlatformLinux, Families: []Distro{DistroRHEL}}
	arch := OSContext{Platform: PlatformLinux, Families: []Distro{DistroArch}}
	cases := []struct {
		host OSContext
		key  FindingKey
		url  string
	}{
		{rhel, "permissions.selinux_disabled", rhelSELinux},
		{rhel, "users.wheel_group_empty", rhelSudo},
		{arch, "users.aur_helper_installed", "https://wiki.archlinux.org/title/Arch_User_Repository#Verify_the_PKGBUILD"},
		{arch, "users.wheel_group_unrestricted", "https://wiki.archlinux.org/title/Sudo#Example_entries"},
		{arch, "users.sudo_nopasswd", "https://wiki.archlinux.org/title/Security#Use_sudo_instead_of_su"},
		{windows, "ssh.config_not_found", msSSH},
		{windows, "ssh.root_login_permitted", msSSH},
		{windows, "users.microsoft_account_no_local_password", "https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_24"},
	}
	for _, c := range cases {
		d, ok := Lookup(c.host, c.key)
		if !ok {
			t.Errorf("%s: no definition for the host", c.key)
			continue
		}
		var urls []string
		for _, ref := range d.Finding().References {
			urls = append(urls, ref.URL)
		}
		if !slices.Contains(urls, c.url) {
			t.Errorf("%s does not carry %s; it carries %v", c.key, c.url, urls)
		}
	}
}

// The citations this audit found wrong are gone: IA-3 from the identity
// provider findings, SI-3 from the firewall profile and SI-16 from SELinux, and
// the two Arch anchors that do not exist on their pages.
func TestCorrectedCitationsAreGone(t *testing.T) {
	for label, d := range allDefinitions() {
		for _, spec := range d.References {
			switch {
			case spec.ID == "IA-3":
				t.Errorf("%s still cites IA-3, device identification, for a finding about users", label)
			case spec.ID == "SI-3" && label == "windows/firewall.profile_inactive":
				t.Errorf("%s still cites SI-3, malicious code protection", label)
			case spec.ID == "SI-16" && label == "linux/rhel/permissions.selinux_disabled":
				t.Errorf("%s still cites SI-16, memory protection", label)
			case strings.HasSuffix(spec.URL, "/AUR#Safety") || strings.HasSuffix(spec.URL, "/Security#sudo"):
				t.Errorf("%s cites %s, an anchor its page does not have", label, spec.URL)
			}
		}
	}
}

func TestReferenceSpecRules(t *testing.T) {
	good := ReferenceSpec{Source: RefTypeURL, Title: "A page", URL: "https://example.com/page", Version: "revision 1", Verified: "2026-11-15"}
	if err := good.validate(); err != nil {
		t.Fatalf("a well-formed NIST reference was refused: %v", err)
	}
	bad := map[string]ReferenceSpec{
		"unknown source":        {Source: "BLOG", ID: "x"},
		"NIST not a control":    {Source: RefTypeNIST, ID: "least privilege"},
		"NIST withdrawn":        {Source: RefTypeNIST, ID: "AC-13"},
		"NIST states a title":   {Source: RefTypeNIST, ID: "AC-6", Title: "Least Privilege"},
		"URL not https":         {Source: RefTypeURL, Title: "t", URL: "http://example.com", Version: "v"},
		"URL without title":     {Source: RefTypeURL, URL: "https://example.com", Version: "v"},
		"CIS without benchmark": {Source: RefTypeCIS, Version: "v1", ID: "1.1"},
		"bad date":              {Source: RefTypeURL, Title: "t", URL: "https://example.com", Version: "v", Verified: "yesterday"},
	}
	for name, spec := range bad {
		if err := spec.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	unverified := good
	unverified.Verified = ""
	if _, ok := unverified.report(); ok {
		t.Error("an unverified reference is reported")
	}
	ref, ok := good.report()
	if !ok || ref.Title != "A page" || ref.URL != "https://example.com/page" || ref.Type != RefTypeURL {
		t.Errorf("URL reference reported as %+v", ref)
	}
	nistRef, ok := ReferenceSpec{Source: RefTypeNIST, ID: "AC-6"}.report()
	if !ok || nistRef.Title != "NIST SP 800-53 Rev 5.2.0 AC-6 (Least Privilege)" {
		t.Errorf("NIST reference reported as %+v", nistRef)
	}

	d := FindingDefinition{CWE: finding.CWE("CWE-284"), References: []ReferenceSpec{{Source: RefTypeNIST, ID: "AC-6"}, good, unverified}}
	refs := d.ToReferences()
	if len(refs) != 3 || refs[0].Type != RefTypeCWE || refs[0].URL != "https://cwe.mitre.org/data/definitions/284.html" || refs[1].Type != RefTypeNIST {
		t.Errorf("references of a definition with a cwe, a NIST control, a verified page and an unchecked one: %+v", refs)
	}
	if got := d.ToCategories(); len(got) != 1 || got[0] != "AC" {
		t.Errorf("categories %v, want [AC]", got)
	}
}

// A technique attached by the NIST to ATT&CK mapping pass reaches the finding a
// checker builds for the host it ran on.
func TestMappedTechniquesReachFindings(t *testing.T) {
	linux := func(family Distro) OSContext {
		return OSContext{Platform: PlatformLinux, Families: []Distro{family}}
	}
	cases := []struct {
		host      OSContext
		key       FindingKey
		technique string
	}{
		{linux(DistroArch), "users.wheel_group_unrestricted", "T1548.003"},
		{linux(DistroDebian), "users.regular_user_admin_privileges", "T1548.003"},
		{linux(DistroDebian), "permissions.sudoers_world_readable", "T1548.003"},
		{linux(DistroRHEL), "permissions.sudoers_world_readable", "T1548.003"},
		{linux(DistroDebian), "ssh.password_auth_not_set", "T1021.004"},
		{linux(DistroDebian), "users.nslcd_lookups_unencrypted", "T1040"},
		{linux(DistroRHEL), "users.nslcd_logins_unencrypted", "T1040"},
		{linux(DistroSUSE), "users.sssd_ldap_id_unencrypted", "T1040"},
		{linux(DistroArch), "users.nslcd_cert_unchecked", "T1557"},
		{linux(DistroDebian), "users.ldap_cert_unchecked", "T1557"},
		{linux(DistroRHEL), "users.sssd_ldap_cert_unchecked", "T1557"},
		{linux(DistroDebian), "users.nslcd_password_readable", "T1552.001"},
	}
	for _, c := range cases {
		d, ok := Lookup(c.host, c.key)
		if !ok {
			t.Errorf("%s: no definition", c.key)
			continue
		}
		var ids []string
		for _, tech := range d.Finding().Techniques {
			ids = append(ids, tech.ID)
		}
		if !slices.Contains(ids, c.technique) {
			t.Errorf("%s carries %v, want %s", c.key, ids, c.technique)
		}
	}
}

var (
	nistBasis = regexp.MustCompile(`^NIST ([A-Z]{2}-\d+(?:\(\d+\))?) maps to `)
	cweBasis  = regexp.MustCompile(`^(CWE-\d+) relates to CAPEC-`)
)

// checkBasis reports what is wrong with one line of a link's basis: it must name
// a NIST control the definition cites, or the weakness its cwe field names.
func checkBasis(d FindingDefinition, cited map[string]bool, basis string) string {
	switch {
	case nistBasis.MatchString(basis):
		if id := nistBasis.FindStringSubmatch(basis)[1]; !cited[id] {
			return "rests on NIST " + id + ", which the definition does not cite"
		}
	case cweBasis.MatchString(basis):
		if id := cweBasis.FindStringSubmatch(basis)[1]; id != string(d.CWE) {
			return "rests on " + id + ", but the definition's weakness is " + string(d.CWE)
		}
	default:
		return "names neither a cited NIST control nor the weakness: " + basis
	}
	return ""
}

// Every technique link says what supports it, and what it names is on the
// definition, so the basis cannot drift from the data it describes.
func TestAttackLinksStateTheirBasis(t *testing.T) {
	for label, d := range allDefinitions() {
		cited := map[string]bool{}
		for _, spec := range d.References {
			if spec.Source == RefTypeNIST {
				cited[spec.ID] = true
			}
		}
		for _, link := range d.AttackTechniques {
			if len(link.Basis) == 0 {
				t.Errorf("%s: %s has no basis", label, link.ID)
			}
			for _, b := range link.Basis {
				if problem := checkBasis(d, cited, b); problem != "" {
					t.Errorf("%s: %s %s", label, link.ID, problem)
				}
			}
		}
	}
}

// A finding's technique carries its basis to every view.
func TestTechniqueBasisReachesFinding(t *testing.T) {
	d, ok := Lookup(OSContext{Platform: PlatformWindows}, "firewall.profile_inactive")
	if !ok {
		t.Fatal("no definition")
	}
	techs := d.Finding().Techniques
	if len(techs) != 1 || techs[0].ID != "T1686" || len(techs[0].Basis) == 0 {
		t.Fatalf("techniques of an inactive firewall profile: %+v", techs)
	}
}
