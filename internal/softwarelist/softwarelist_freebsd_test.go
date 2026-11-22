//go:build freebsd

// internal/softwarelist/softwarelist_freebsd_test.go

package softwarelist

import (
	"context"
	"slices"
	"testing"
)

// The lines are what pkg query printed on FreeBSD 15.1 with its base system
// installed as packages.
func TestParsePkgQuery(t *testing.T) {
	output := "FreeBSD-acct\t15.1\tbase/FreeBSD-acct\tFreeBSD:15:amd64\n" +
		"FreeBSD-acpi-dbg\t15.1\tbase/FreeBSD-acpi-dbg\tFreeBSD:15:amd64\n"
	got, err := parsePkgQuery(output)
	if err != nil {
		t.Fatal(err)
	}
	want := []SoftwareEntry{
		{Name: "FreeBSD-acct", Version: "15.1", Manager: ManagerPkg, Architecture: "FreeBSD:15:amd64", Source: "base/FreeBSD-acct"},
		{Name: "FreeBSD-acpi-dbg", Version: "15.1", Manager: ManagerPkg, Architecture: "FreeBSD:15:amd64", Source: "base/FreeBSD-acpi-dbg"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("parsePkgQuery() =\n  %+v\nwant\n  %+v", got, want)
	}

	for _, line := range []string{"FreeBSD-acct\t15.1", "\t15.1\tbase/x\tFreeBSD:15:amd64"} {
		if _, err := parsePkgQuery(line + "\n"); err == nil {
			t.Errorf("%q was read as a package", line)
		}
	}
}

// The host the tests run on answers the query, and every entry has a name, a
// version and an origin.
func TestInventoryOfThisHost(t *testing.T) {
	entries, err := getPlatformSoftwareList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no packages read")
	}
	for _, e := range entries {
		if e.Name == "" || e.Version == "" || e.Source == "" || e.Manager != ManagerPkg {
			t.Errorf("%+v lacks a name, a version, an origin or its package manager", e)
		}
	}
}
