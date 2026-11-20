// internal/security/registry/defines_test.go

package registry

import "testing"

// A platform defines a check when a key of that check is in one of its
// definition sets. FreeBSD has the users and SSH rules, a Linux family every
// check through the common set, and a platform with no definitions none.
func TestDefines(t *testing.T) {
	freebsd := OSContext{Platform: PlatformUnix, Families: []Distro{DistroFreeBSD}}
	linux := OSContext{Platform: PlatformLinux, Families: []Distro{DistroSUSE}}
	openbsd := OSContext{Platform: PlatformUnix, Families: []Distro{DistroOpenBSD}}

	cases := []struct {
		ctx   OSContext
		check string
		want  bool
	}{
		{freebsd, "users", true},
		{freebsd, "ssh", true},
		{freebsd, "firewall", false},
		{freebsd, "permissions", false},
		{linux, "users", true},
		{linux, "ssh", true},
		{linux, "firewall", true},
		{linux, "permissions", true},
		{linux, "user", false},
		{openbsd, "users", false},
	}
	for _, tc := range cases {
		if got := Defines(tc.ctx, tc.check); got != tc.want {
			t.Errorf("%s on %s: %v, want %v", tc.check, tc.ctx.DisplayLabel(), got, tc.want)
		}
	}

	if !HasDefinitions(freebsd) || HasDefinitions(openbsd) {
		t.Error("FreeBSD has definitions and OpenBSD has none")
	}
}

// The FreeBSD file defines the SSH rules its sshd is judged by, the three it
// shares with Linux at Linux's baseline, and neither rule for a directive left
// unset: its manual states the default, so an unset directive is judged.
func TestFreeBSDSSHRules(t *testing.T) {
	freebsd := OSContext{Platform: PlatformUnix, Families: []Distro{DistroFreeBSD}}
	linux := OSContext{Platform: PlatformLinux, Families: []Distro{DistroGeneric}}

	for _, key := range []FindingKey{"ssh.config_not_found", "ssh.root_login_permitted", "ssh.password_auth_enabled"} {
		here, ok := Lookup(freebsd, key)
		there, _ := Lookup(linux, key)
		if !ok || here.CVSSVector != there.CVSSVector || here.CWE != there.CWE {
			t.Errorf("%s: FreeBSD %v %s %s, Linux %s %s", key, ok, here.CVSSVector, here.CWE, there.CVSSVector, there.CWE)
		}
	}
	if _, ok := Lookup(freebsd, "ssh.empty_passwords_permitted"); !ok {
		t.Error("ssh.empty_passwords_permitted: no definition for FreeBSD")
	}
	for _, key := range []FindingKey{"ssh.permit_root_login_not_set", "ssh.password_auth_not_set"} {
		if _, ok := Lookup(freebsd, key); ok {
			t.Errorf("%s is defined for FreeBSD", key)
		}
	}
}

// The FreeBSD file defines the rules its reader names, and not the rule that
// asks for root's password to be locked: su asks for that password.
func TestFreeBSDUsersRules(t *testing.T) {
	freebsd := OSContext{Platform: PlatformUnix, Families: []Distro{DistroFreeBSD}}

	for _, key := range []FindingKey{
		"users.empty_password_hash",
		"users.no_password_login_shell",
		"users.uid_zero_non_root",
		"users.regular_user_admin_privileges",
		"users.sudo_nopasswd",
		"users.su_group_member",
		"users.su_unrestricted",
		"users.login_shell_present",
		"users.system_account_login_shell",
		"users.nologin_account_password_set",
	} {
		if _, ok := Lookup(freebsd, key); !ok {
			t.Errorf("%s: no definition for FreeBSD", key)
		}
	}
	if _, ok := Lookup(freebsd, "users.root_account_unlocked"); ok {
		t.Error("users.root_account_unlocked is defined for FreeBSD")
	}

	// A condition both platforms define is scored alike.
	linux := OSContext{Platform: PlatformLinux, Families: []Distro{DistroGeneric}}
	for _, key := range []FindingKey{
		"users.empty_password_hash",
		"users.no_password_login_shell",
		"users.uid_zero_non_root",
		"users.regular_user_admin_privileges",
		"users.sudo_nopasswd",
		"users.login_shell_present",
	} {
		here, _ := Lookup(freebsd, key)
		there, _ := Lookup(linux, key)
		if here.CVSSVector != there.CVSSVector || here.CWE != there.CWE {
			t.Errorf("%s: FreeBSD %s %s, Linux %s %s", key, here.CVSSVector, here.CWE, there.CVSSVector, there.CWE)
		}
	}
}
