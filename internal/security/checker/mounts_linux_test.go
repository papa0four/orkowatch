//go:build linux

// internal/security/checker/mounts_linux_test.go

package checker

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// The mount table and filesystem list of an Ubuntu 22.04 host, read whole.
func ubuntuMounts(t *testing.T) []mount {
	t.Helper()
	filesystems, err := os.ReadFile("testdata/mounts/ubuntu.filesystems")
	if err != nil {
		t.Fatal(err)
	}
	table, err := os.ReadFile("testdata/mounts/ubuntu.mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	mounts, err := parseMountInfo(string(table), blockBacked(string(filesystems)))
	if err != nil {
		t.Fatal(err)
	}
	return mounts
}

// The plan for a whole host: every local and memory filesystem is walked
// once, and each mount left out is left out for the reason observed on the
// host the table was read from.
func TestPlanFromUbuntuMountTable(t *testing.T) {
	plan := planScan("/", ubuntuMounts(t))

	wantStarts := []string{
		"/dev",
		"/dev/shm",
		"/init",
		"/mnt/wsl",
		"/mnt/wslg",
		"/mnt/wslg/doc",
		"/mnt/wslg/versions.txt",
		"/run",
		"/run/lock",
		"/run/user/1000",
		"/snap",
		"/usr/lib/modules/6.18.58.1-microsoft-standard-WSL2",
		"/usr/lib/wsl/lib",
		"/usr/src/linux-headers-6.18.58.1-microsoft-standard-WSL2",
		"/var/lib/docker",
	}
	if !slices.Equal(plan.starts, wantStarts) {
		t.Errorf("walked from:\n  %s\nwant:\n  %s", strings.Join(plan.starts, "\n  "), strings.Join(wantStarts, "\n  "))
	}

	wantLeft := []string{
		"/dev/hugepages: pseudo-filesystem",
		"/dev/mqueue: pseudo-filesystem",
		"/dev/pts: pseudo-filesystem",
		"/mnt/c: network filesystem",
		"/mnt/wslg/distro: same filesystem as another path, walked at /",
		"/mnt/wslg/run/user/1000: same filesystem as another path, walked at /run/user/1000",
		"/proc/sys/fs/binfmt_misc/status: same filesystem as another path, walked at /run",
		"/proc/sys/fs/binfmt_misc: pseudo-filesystem",
		"/proc: pseudo-filesystem",
		"/run/shm: same filesystem as another path, walked at /dev/shm",
		"/run/user: hidden beneath another mount",
		"/run/user: same filesystem as another path, walked at /mnt/wslg",
		"/snap/bare/5: FUSE filesystem",
		"/snap/core22/2139: FUSE filesystem",
		"/snap/core22/2163: FUSE filesystem",
		"/snap/gtk-common-themes/1535: FUSE filesystem",
		"/snap/snapd/25577: FUSE filesystem",
		"/snap/snapd/27738: FUSE filesystem",
		"/snap/ubuntu-desktop-installer/1284: FUSE filesystem",
		"/snap/ubuntu-desktop-installer/1286: FUSE filesystem",
		"/sys/fs/cgroup: pseudo-filesystem",
		"/sys/fs/fuse/connections: pseudo-filesystem",
		"/sys/kernel/debug: pseudo-filesystem",
		"/sys/kernel/tracing: pseudo-filesystem",
		"/sys: pseudo-filesystem",
		"/tmp/.X11-unix: same filesystem as another path, walked at /mnt/wslg",
		"/usr/lib/wsl/drivers: network filesystem",
	}
	if got := left(plan); !slices.Equal(got, wantLeft) {
		t.Errorf("left out:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(wantLeft, "\n  "))
	}
}

func TestParseMountInfoLine(t *testing.T) {
	backed := map[string]bool{"ext4": true}
	line, err := parseMountInfoLine(
		`605 85 7:0 /sub\040dir /mnt/my\040disk rw,relatime shared:1 master:2 - ext4 /dev/loop0 rw`, backed)
	if err != nil {
		t.Fatal(err)
	}
	want := mount{point: "/mnt/my disk", fstype: "ext4", shows: "/sub dir", fsid: 7 << 32, kind: mountLocal}
	if line.mount != want || line.id != 605 || line.parent != 85 {
		t.Errorf("parsed %+v, want mount %+v with id 605 and parent 85", line, want)
	}

	// No optional field at all, and a source the kernel wrote an escaped
	// backslash into.
	line, err = parseMountInfoLine(`134 85 0:69 / /mnt/c rw,noatime - 9p C:\134 rw`, backed)
	if err != nil || line.point != "/mnt/c" || line.fstype != "9p" || line.kind != mountNetwork || line.fsid != 69 {
		t.Errorf("parsed %+v, %v; want /mnt/c as a 9p network mount on device 0:69", line, err)
	}

	for _, text := range []string{
		`134 85 0:69 / /mnt/c rw,noatime`,
		`134 85 0:69 / /mnt/c rw,noatime -`,
		`x 85 0:69 / /mnt/c rw - 9p none rw`,
		`134 y 0:69 / /mnt/c rw - 9p none rw`,
		`134 85 069 / /mnt/c rw - 9p none rw`,
		`134 85 a:b / /mnt/c rw - 9p none rw`,
	} {
		if _, err := parseMountInfoLine(text, backed); err == nil {
			t.Errorf("%q was read as a mount", text)
		}
	}
	if _, err := parseMountInfo("36 35 98:0 / / rw - ext4 /dev/root rw\nnot a mount\n", backed); err == nil {
		t.Error("a table holding a line that is not a mount was read")
	}
}

func TestUnescapeMountInfo(t *testing.T) {
	for field, want := range map[string]string{
		`/plain`:        "/plain",
		`/a\040b`:       "/a b",
		`/tab\011here`:  "/tab\there",
		`/back\134`:     `/back\`,
		`/trailing\`:    `/trailing\`,
		`/short\04`:     `/short\04`,
		`/not\9octal`:   `/not\9octal`,
		`/two\040\040x`: "/two  x",
	} {
		if got := unescapeMountInfo(field); got != want {
			t.Errorf("unescapeMountInfo(%q) = %q, want %q", field, got, want)
		}
	}
}

// A type that needs a block device is local on the kernel's word; one that
// does not is judged by name, and a name nothing judges is left unjudged.
func TestLinuxKind(t *testing.T) {
	backed := blockBacked("nodev\tsysfs\nnodev\ttmpfs\n\text4\n\tfuseblk\nnodev\tfuse\n\tbtrfs\n")
	for fstype, want := range map[string]mountKind{
		"ext4":          mountLocal,
		"btrfs":         mountLocal,
		"fuseblk":       mountLocal,
		"fuseblk.ntfs":  mountLocal,
		"tmpfs":         mountLocal,
		"devtmpfs":      mountLocal,
		"overlay":       mountLocal,
		"zfs":           mountLocal,
		"sysfs":         mountPseudo,
		"cgroup2":       mountPseudo,
		"nfs":           mountNetwork,
		"nfs4":          mountNetwork,
		"cifs":          mountNetwork,
		"smb3":          mountNetwork,
		"9p":            mountNetwork,
		"fuse":          mountFUSE,
		"fuse.sshfs":    mountFUSE,
		"fuse.snapfuse": mountFUSE,
		"oddfs":         mountUnjudged,
	} {
		if got := linuxKind(fstype, backed); got != want {
			t.Errorf("linuxKind(%q) = %d, want %d", fstype, got, want)
		}
	}
	if got := linuxKind("btrfs", map[string]bool{}); got != mountUnjudged {
		t.Errorf("btrfs on a kernel that does not list it = %d, want unjudged", got)
	}
}

// A mount is hidden by one made over its mount point, by one made over a
// directory above it, and with any mount it lies in that is itself hidden.
func TestHiddenMounts(t *testing.T) {
	table := strings.Join([]string{
		`1 0 8:1 / / rw - ext4 /dev/sda1 rw`,
		`2 1 0:20 / /run rw - tmpfs none rw`,
		`3 2 0:21 / /run/user rw - tmpfs none rw`,
		`4 3 0:22 / /run/user rw - tmpfs none rw`,
		`5 1 0:23 / /srv/data/deep rw - tmpfs none rw`,
		`6 5 0:24 / /srv/data/deep/er rw - tmpfs none rw`,
		`7 1 8:2 / /srv/data rw - ext4 /dev/sda2 rw`,
		`8 1 8:3 / /srv/database rw - ext4 /dev/sda3 rw`,
	}, "\n")
	mounts, err := parseMountInfo(table, map[string]bool{"ext4": true})
	if err != nil {
		t.Fatal(err)
	}

	var hidden []string
	for _, m := range mounts {
		if m.hidden {
			hidden = append(hidden, m.point+" "+m.fstype)
		}
	}
	want := []string{"/run/user tmpfs", "/srv/data/deep tmpfs", "/srv/data/deep/er tmpfs"}
	if !slices.Equal(hidden, want) {
		t.Errorf("hidden mounts %q, want %q", hidden, want)
	}
	if mounts[3].hidden {
		t.Error("the mount made over /run/user is itself hidden")
	}
}

// The host the tests run on has a mount table the reading accepts, with its
// root filesystem in it.
func TestReadMountsOnThisHost(t *testing.T) {
	mounts, judged, err := readMounts()
	if err != nil || !judged {
		t.Fatalf("readMounts() judged=%v, err=%v", judged, err)
	}
	if !slices.ContainsFunc(mounts, func(m mount) bool { return m.point == "/" && !m.hidden }) {
		t.Errorf("no mount at / among %d mounts", len(mounts))
	}
}
