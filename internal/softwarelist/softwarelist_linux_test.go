//go:build linux

// internal/softwarelist/softwarelist_linux_test.go

package softwarelist

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// The lines below are what each package manager printed on a host of it:
// dpkg on Debian 12, rpm on AlmaLinux 9 and openSUSE Tumbleweed, apk on
// Alpine 3.20 and pacman on Arch Linux.

func TestParseDpkg(t *testing.T) {
	output := strings.Join([]string{
		"bash\t5.2.15-2+b13\tamd64\tbash\t5.2.15-2\tinstalled",
		"bsdutils\t1:2.38.1-5+deb12u3\tamd64\tutil-linux\t2.38.1-5+deb12u3\tinstalled",
		"libacl1\t2.3.1-3\tamd64\tacl\t2.3.1-3\tinstalled",
		"adduser\t3.134\tall\tadduser\t3.134\tconfig-files",
		"",
	}, "\n")
	got, err := parseDpkg(output)
	if err != nil {
		t.Fatal(err)
	}
	want := []SoftwareEntry{
		// A rebuild: the binary package carries a suffix its source does not.
		{Name: "bash", Version: "5.2.15-2+b13", Manager: ManagerDpkg, Architecture: "amd64", Source: "bash", SourceVersion: "5.2.15-2"},
		// A binary package with an epoch its source does not have.
		{Name: "bsdutils", Version: "1:2.38.1-5+deb12u3", Manager: ManagerDpkg, Architecture: "amd64", Source: "util-linux", SourceVersion: "2.38.1-5+deb12u3"},
		{Name: "libacl1", Version: "2.3.1-3", Manager: ManagerDpkg, Architecture: "amd64", Source: "acl", SourceVersion: "2.3.1-3"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("parseDpkg() =\n  %+v\nwant\n  %+v", got, want)
	}

	for _, line := range []string{"bash\t5.2.15-2+b13", "\t1.0\tamd64\tx\t1.0\tinstalled", "a\tb\tc\td\te\tf\tg"} {
		if _, err := parseDpkg(line + "\n"); err == nil {
			t.Errorf("%q was read as a package", line)
		}
	}
}

func TestParseRPM(t *testing.T) {
	output := strings.Join([]string{
		"gdbm-libs\t1\t1.23\t1.el9\tx86_64\tgdbm-1.23-1.el9.src.rpm",
		"tzdata\t(none)\t2026f\t1.el9_9\tnoarch\ttzdata-2026f-1.el9_9.src.rpm",
		"python3-setuptools-wheel\t(none)\t53.0.0\t15.el9\tnoarch\tpython-setuptools-53.0.0-15.el9.src.rpm",
		"boost-license1_92_0\t(none)\t1.92.0\t1.1\tnoarch\tboost-base-1.92.0-1.1.src.rpm",
		"gpg-pubkey\t(none)\tb86b3716\t61e69f29\t(none)\t(none)",
		"",
	}, "\n")
	got, err := parseRPM(output)
	if err != nil {
		t.Fatal(err)
	}
	want := []SoftwareEntry{
		{Name: "gdbm-libs", Version: "1:1.23-1.el9", Manager: ManagerRPM, Architecture: "x86_64", Source: "gdbm"},
		{Name: "tzdata", Version: "2026f-1.el9_9", Manager: ManagerRPM, Architecture: "noarch", Source: "tzdata"},
		{Name: "python3-setuptools-wheel", Version: "53.0.0-15.el9", Manager: ManagerRPM, Architecture: "noarch", Source: "python-setuptools"},
		{Name: "boost-license1_92_0", Version: "1.92.0-1.1", Manager: ManagerRPM, Architecture: "noarch", Source: "boost-base"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("parseRPM() =\n  %+v\nwant\n  %+v", got, want)
	}

	if _, err := parseRPM("tzdata\t(none)\t2026f\n"); err == nil {
		t.Error("a line short of its fields was read as a package")
	}
}

func TestRPMSourceName(t *testing.T) {
	for file, want := range map[string]string{
		"gdbm-1.23-1.el9.src.rpm":                     "gdbm",
		"python-setuptools-53.0.0-15.el9.src.rpm":     "python-setuptools",
		"openSUSE-release-15.6-lp156.417.4.1.src.rpm": "openSUSE-release",
		"firmware-1.0-2.nosrc.rpm":                    "firmware",
		"(none)":                                      "",
		"":                                            "",
		"1.0-2.src.rpm":                               "",
		"name-only.src.rpm":                           "",
		"gdbm-1.23-1.el9.x86_64.rpm":                  "",
	} {
		if got := rpmSourceName(file); got != want {
			t.Errorf("rpmSourceName(%q) = %q, want %q", file, got, want)
		}
	}
}

func TestParseAPK(t *testing.T) {
	data := strings.Join([]string{
		"C:Q1qKcZ+j23xssAXmgQhkOO8dHnbWw=",
		"P:alpine-baselayout",
		"V:3.6.5-r0",
		"A:x86_64",
		"S:8515",
		"T:Alpine base dir structure and init scripts",
		"U:https://git.alpinelinux.org/cgit/aports/tree/main/alpine-baselayout",
		"o:alpine-baselayout",
		"D:alpine-baselayout-data=3.6.5-r0 /bin/sh",
		"F:etc/profile.d",
		"R:README",
		"a:0:0:600",
		"",
		"P:busybox-binsh",
		"V:1.36.1-r31",
		"A:x86_64",
		"o:busybox",
		"",
		"C:Q1orphan",
		"T:a record with no name",
		"",
	}, "\n")
	want := []SoftwareEntry{
		{Name: "alpine-baselayout", Version: "3.6.5-r0", Manager: ManagerAPK, Architecture: "x86_64", Source: "alpine-baselayout"},
		{Name: "busybox-binsh", Version: "1.36.1-r31", Manager: ManagerAPK, Architecture: "x86_64", Source: "busybox"},
	}
	if got := parseAPK(data); !slices.Equal(got, want) {
		t.Errorf("parseAPK() =\n  %+v\nwant\n  %+v", got, want)
	}

	// The last record of the file need not end in a blank line.
	if got := parseAPK("P:zlib\nV:1.3.1-r1\nA:x86_64\no:zlib"); len(got) != 1 || got[0].Name != "zlib" {
		t.Errorf("a record at the end of the file was read as %+v", got)
	}
}

func TestParsePacmanDesc(t *testing.T) {
	desc := strings.Join([]string{
		"%NAME%", "ca-certificates-mozilla", "",
		"%VERSION%", "3.133-1", "",
		"%BASE%", "nss", "",
		"%DESC%", "Mozilla's set of trusted CA certificates", "",
		"%ARCH%", "x86_64", "",
		"%DEPENDS%", "ca-certificates-utils>=20181109-3", "",
	}, "\n")
	got, err := parsePacmanDesc(desc)
	want := SoftwareEntry{Name: "ca-certificates-mozilla", Version: "3.133-1", Manager: ManagerPacman, Architecture: "x86_64", Source: "nss"}
	if err != nil || got != want {
		t.Errorf("parsePacmanDesc() = %+v, %v; want %+v", got, err, want)
	}

	epoch, err := parsePacmanDesc("%NAME%\niptables\n\n%VERSION%\n1:1.8.13-1\n\n%BASE%\niptables\n\n%ARCH%\nx86_64\n")
	if err != nil || epoch.Version != "1:1.8.13-1" {
		t.Errorf("a version with an epoch was read as %+v, %v", epoch, err)
	}

	for _, broken := range []string{"", "%NAME%\nacl\n", "%VERSION%\n2.4.0-1\n", "%DESC%\n%NAME%\n"} {
		if _, err := parsePacmanDesc(broken); err == nil {
			t.Errorf("%q was read as a package", broken)
		}
	}
}

// The host the tests run on has a package manager that is read, and every
// entry says which manager it came from and what version it is.
func TestInventoryOfThisHost(t *testing.T) {
	entries, err := getPlatformSoftwareList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no packages read")
	}
	for _, e := range entries {
		if e.Name == "" || e.Version == "" || e.Manager == "" {
			t.Errorf("%+v lacks a name, a version or its package manager", e)
		}
		if e.Name == rpmPublicKey {
			t.Errorf("a signing key is listed as software: %+v", e)
		}
	}
	if !slices.IsSortedFunc(entries, func(a, b SoftwareEntry) int {
		return strings.Compare(a.Manager+"\x00"+a.Name, b.Manager+"\x00"+b.Name)
	}) {
		t.Error("the inventory is not in order of package manager and name")
	}
}
