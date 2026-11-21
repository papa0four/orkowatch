//go:build freebsd

// internal/security/checker/mounts_freebsd_test.go

package checker

import (
	"encoding/hex"
	"slices"
	"strings"
	"testing"
)

// vfs.conflist as a FreeBSD 15.1 host installed on ZFS returned it, one
// record to a line: devfs, msdosfs, nfs, procfs, tmpfs, cd9660, ufs, zfs,
// nullfs and fdescfs.
const conflist151 = `
0000000000000000 64657666730000000000000000000000 71000000 01000000 00004800 00000000 0000000000000000
0000000000000000 6d73646f736673000000000000000000 32000000 01000000 00000000 00000000 0000000000000000
0000000000000000 6e667300000000000000000000000000 3a000000 01000000 00000201 00000000 0000000000000000
0000000000000000 70726f63667300000000000000000000 02000000 01000000 00004800 00000000 0000000000000000
0000000000000000 746d7066730000000000000000000000 87000000 01000000 00004000 00000000 0000000000000000
0000000000000000 63643936363000000000000000000000 bd000000 00000000 00000400 00000000 0000000000000000
0000000000000000 75667300000000000000000000000000 35000000 01000000 00000004 00000000 0000000000000000
0000000000000000 7a667300000000000000000000000000 de000000 0c000000 0000c004 00000000 0000000000000000
0000000000000000 6e756c6c667300000000000000000000 29000000 01000000 00005002 00000000 0000000000000000
0000000000000000 66646573636673000000000000000000 59000000 01000000 00004800 00000000 0000000000000000
`

func TestFreeBSDKindFromKernelFlags(t *testing.T) {
	raw, err := hex.DecodeString(strings.Join(strings.Fields(conflist151), ""))
	if err != nil {
		t.Fatal(err)
	}
	flags, err := parseVFSConf(raw)
	if err != nil {
		t.Fatal(err)
	}

	for fstype, want := range map[string]mountKind{
		"ufs":     mountLocal,
		"zfs":     mountLocal,
		"msdosfs": mountLocal,
		"tmpfs":   mountLocal,
		"cd9660":  mountLocal,
		"devfs":   mountPseudo,
		"procfs":  mountPseudo,
		"fdescfs": mountPseudo,
		"nfs":     mountNetwork,
		"nullfs":  mountAlias,
		"oddfs":   mountUnjudged,
	} {
		if got := freebsdKind(fstype, flags); got != want {
			t.Errorf("freebsdKind(%q) = %d, want %d", fstype, got, want)
		}
	}

	if _, err := parseVFSConf(raw[:len(raw)-1]); err == nil {
		t.Error("a reading cut short of a whole record was accepted")
	}
	if _, err := parseVFSConf(nil); err == nil {
		t.Error("an empty reading was accepted")
	}
}

// The host the tests run on: its root is a local filesystem, devfs is a
// pseudo-filesystem, and every type mounted is one the kernel's table lists.
func TestReadMountsOnThisHost(t *testing.T) {
	mounts, judged, err := readMounts()
	if err != nil || !judged {
		t.Fatalf("readMounts() judged=%v, err=%v", judged, err)
	}
	at := func(point string) (mount, bool) {
		i := slices.IndexFunc(mounts, func(m mount) bool { return m.point == point && !m.hidden })
		if i < 0 {
			return mount{}, false
		}
		return mounts[i], true
	}

	if root, ok := at("/"); !ok || root.kind != mountLocal || root.fsid == 0 {
		t.Errorf("the mount at / = %+v, found %v; want a local filesystem with an identifier", root, ok)
	}
	if dev, ok := at("/dev"); !ok || dev.kind != mountPseudo {
		t.Errorf("the mount at /dev = %+v, found %v; want a pseudo-filesystem", dev, ok)
	}
	for _, m := range mounts {
		if m.kind == mountUnjudged {
			t.Errorf("%s (%s) is unjudged", m.point, m.fstype)
		}
	}
}
