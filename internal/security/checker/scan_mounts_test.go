//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/security/checker/scan_mounts_test.go

package checker

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/treewalk"
)

// Filesystem identities for the tables below. Only their being equal or not
// matters.
const (
	fsRoot uint64 = iota + 1
	fsDisk
	fsDev
	fsShm
	fsRun
	fsSession
	fsOther
)

func local(point, shows string, fsid uint64) mount {
	return mount{point: point, fstype: "ext4", shows: shows, fsid: fsid, kind: mountLocal}
}

func other(point, fstype string, kind mountKind) mount {
	return mount{point: point, fstype: fstype, shows: "/", fsid: fsOther, kind: kind}
}

// left returns the mounts a plan left out as "point: reason[, detail]".
func left(plan scanPlan) []string {
	var got []string
	for _, l := range plan.left {
		line := l.point + ": " + leftReasons[l.reason].text
		if l.detail != "" {
			line += ", " + l.detail
		}
		got = append(got, line)
	}
	slices.Sort(got)
	return got
}

func TestPlanScan(t *testing.T) {
	// The shape of the mount table read from an Ubuntu host: the root
	// filesystem bound onto itself at two paths and mounted again beneath a
	// memory filesystem, one memory filesystem at two paths, a subtree of
	// another at a third, and a mount covered by a later one.
	host := []mount{
		local("/", "/", fsRoot),
		local("/snap", "/snap", fsRoot),
		local("/var/lib/docker", "/var/lib/docker", fsRoot),
		local("/dev", "/", fsDev),
		local("/dev/shm", "/", fsShm),
		local("/run", "/", fsRun),
		local("/run/shm", "/", fsShm),
		{point: "/run/user", fstype: "tmpfs", shows: "/", fsid: fsOther, kind: mountLocal, hidden: true},
		local("/run/user", "/run/user", fsSession),
		local("/mnt/wslg", "/", fsSession),
		local("/mnt/wslg/distro", "/", fsRoot),
		local("/tmp/.X11-unix", "/.X11-unix", fsSession),
		other("/proc", "proc", mountPseudo),
		other("/proc/sys/fs/binfmt_misc", "binfmt_misc", mountPseudo),
		other("/mnt/c", "9p", mountNetwork),
		other("/snap/core22/2139", "fuse.snapfuse", mountFUSE),
		other("/srv/odd", "oddfs", mountUnjudged),
	}

	// One image mounted, mounted again, bound whole and bound by a
	// subdirectory, beside a memory filesystem.
	made := []mount{
		local("/", "/", fsRoot),
		local("/tmp/obs/disk", "/", fsDisk),
		local("/tmp/obs/bind", "/sub", fsDisk),
		local("/tmp/obs/twice", "/", fsDisk),
		local("/tmp/obs/whole", "/", fsDisk),
		local("/tmp/obs/mem", "/", fsShm),
	}

	// A FreeBSD table: an alias of a directory on a second filesystem, an
	// alias of one outside the jail it is mounted in, and an alias of a
	// directory on a network mount.
	aliases := []mount{
		local("/", "/", fsRoot),
		local("/mnt/disk", "/", fsDisk),
		{point: "/mnt/null", fstype: "nullfs", shows: "/", source: "/mnt/disk/sub", fsid: fsDev, kind: mountAlias},
		{point: "/jail/src", fstype: "nullfs", shows: "/", source: "/usr/src", fsid: fsShm, kind: mountAlias},
		other("/mnt/nfs", "nfs", mountNetwork),
		{point: "/mnt/far", fstype: "nullfs", shows: "/", source: "/mnt/nfs/share", fsid: fsRun, kind: mountAlias},
	}

	tests := []struct {
		name       string
		root       string
		mounts     []mount
		wantStarts []string
		wantLeft   []string
	}{
		{
			name: "a whole host", root: "/", mounts: host,
			wantStarts: []string{"/dev", "/dev/shm", "/mnt/wslg", "/run", "/snap", "/var/lib/docker"},
			wantLeft: []string{
				"/mnt/c: network filesystem",
				"/mnt/wslg/distro: same filesystem as another path, walked at /",
				"/proc/sys/fs/binfmt_misc: pseudo-filesystem",
				"/proc: pseudo-filesystem",
				"/run/shm: same filesystem as another path, walked at /dev/shm",
				"/run/user: hidden beneath another mount",
				"/run/user: same filesystem as another path, walked at /mnt/wslg",
				"/snap/core22/2139: FUSE filesystem",
				"/srv/odd: no judgement for the filesystem type",
				"/tmp/.X11-unix: same filesystem as another path, walked at /mnt/wslg",
			},
		},
		{
			name: "a subtree whose whole filesystem lies outside the root", root: "/tmp", mounts: host,
			wantStarts: []string{"/tmp/.X11-unix"},
		},
		{
			name: "the root is itself a second mount of the root filesystem", root: "/mnt/wslg/distro", mounts: host,
		},
		{
			name: "one filesystem at four paths", root: "/tmp/obs", mounts: made,
			wantStarts: []string{"/tmp/obs/disk", "/tmp/obs/mem"},
			wantLeft: []string{
				"/tmp/obs/bind: same filesystem as another path, walked at /tmp/obs/disk",
				"/tmp/obs/twice: same filesystem as another path, walked at /tmp/obs/disk",
				"/tmp/obs/whole: same filesystem as another path, walked at /tmp/obs/disk",
			},
		},
		{
			name: "a subtree bind inside the scan root's own filesystem", root: "/",
			mounts:   []mount{local("/", "/", fsRoot), local("/srv/www", "/var/www", fsRoot)},
			wantLeft: []string{"/srv/www: same filesystem as another path, walked at /"},
		},
		{
			name: "a subtree the root's walk cannot arrive at", root: "/",
			mounts: []mount{
				local("/", "/", fsRoot), other("/var", "nfs", mountNetwork), local("/srv/www", "/var/www", fsRoot),
			},
			wantStarts: []string{"/srv/www"},
			wantLeft:   []string{"/var: network filesystem"},
		},
		{
			name: "a local filesystem beneath a mount that is not walked", root: "/",
			mounts:     []mount{local("/", "/", fsRoot), other("/mnt/c", "9p", mountNetwork), local("/mnt/c/disk", "/", fsDisk)},
			wantStarts: []string{"/mnt/c/disk"},
			wantLeft:   []string{"/mnt/c: network filesystem"},
		},
		{
			name: "aliases across a whole host", root: "/", mounts: aliases,
			wantStarts: []string{"/mnt/disk", "/mnt/far"},
			wantLeft: []string{
				"/jail/src: same filesystem as another path, shows /usr/src",
				"/mnt/nfs: network filesystem",
				"/mnt/null: same filesystem as another path, shows /mnt/disk/sub",
			},
		},
		{
			name: "an alias of a directory outside the scan root", root: "/jail", mounts: aliases,
			wantStarts: []string{"/jail/src"},
		},
		{
			name: "the shorter of two paths to one filesystem", root: "/",
			mounts:     []mount{local("/", "/", fsRoot), local("/a/long/way/down", "/", fsDisk), local("/z", "/", fsDisk)},
			wantStarts: []string{"/z"},
			wantLeft:   []string{"/a/long/way/down: same filesystem as another path, walked at /z"},
		},
		{
			name: "no mount table", root: "/", mounts: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := planScan(tt.root, tt.mounts)
			if !slices.Equal(plan.starts, tt.wantStarts) {
				t.Errorf("walked from %v, want %v", plan.starts, tt.wantStarts)
			}
			if got := left(plan); !slices.Equal(got, tt.wantLeft) {
				t.Errorf("left out:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(tt.wantLeft, "\n  "))
			}
			for _, start := range plan.starts {
				if _, ok := plan.stops[start]; !ok {
					t.Errorf("the descent does not stop at %s, which is walked from the plan", start)
				}
			}
		})
	}
}

// The mount walked of several is the same whatever order the table lists
// them in.
func TestPlanScanIsStable(t *testing.T) {
	mounts := []mount{
		local("/", "/", fsRoot), local("/b", "/", fsDisk), local("/a", "/", fsDisk), local("/c", "/sub", fsDisk),
	}
	want := planScan("/", mounts).starts
	slices.Reverse(mounts)
	if got := planScan("/", mounts).starts; !slices.Equal(got, want) || !slices.Equal(got, []string{"/a"}) {
		t.Errorf("walked from %v and, with the table reversed, %v; want [/a] both times", want, got)
	}
}

// Each reason is stated once with every mount left out for it, and the scan
// rules pass over a pseudo-filesystem left out but not over a filesystem
// nothing judged.
func TestReportScanNamesWhatWasLeft(t *testing.T) {
	linux := registry.OSContext{Platform: registry.PlatformLinux, Families: []registry.Distro{registry.DistroGeneric}}
	meant := []leftMount{
		{point: "/sys", fstype: "sysfs", reason: leftPseudo},
		{point: "/proc", fstype: "proc", reason: leftPseudo},
		{point: "/mnt/c", fstype: "9p", reason: leftNetwork},
		{point: "/run/shm", fstype: "tmpfs", reason: leftSame, detail: "walked at /dev/shm"},
	}

	r := newReport(checkIdentity{osCtx: linux})
	reportScan(r, fsScan{left: slices.Clone(meant), scanned: 3}, nil)
	details := strings.Join(r.finish().Details, "\n")
	for _, want := range []string{
		"[*] Not walked, pseudo-filesystem: /proc (proc), /sys (sysfs)",
		"[*] Not walked, network filesystem: /mnt/c (9p)",
		"[*] Not walked, same filesystem as another path: /run/shm (tmpfs, walked at /dev/shm)",
	} {
		if !strings.Contains(details, want) {
			t.Errorf("the report lacks %q:\n%s", want, details)
		}
	}
	for _, key := range []registry.FindingKey{ruleSetID, ruleWorldWritable, ruleUnowned} {
		if got := conditions(r)[key].Result; got != finding.ResultPass {
			t.Errorf("%s = %s with only mounts left out as meant, want pass", key, got)
		}
	}

	gaps := append(slices.Clone(meant),
		leftMount{point: "/srv/odd", fstype: "oddfs", reason: leftUnjudged},
		leftMount{point: "/media/late", reason: leftUnlisted})
	r = newReport(checkIdentity{osCtx: linux})
	reportScan(r, fsScan{left: gaps, scanned: 3}, nil)
	details = strings.Join(r.finish().Details, "\n")
	for _, want := range []string{
		"[!] Not walked, no judgement for the filesystem type: /srv/odd (oddfs)",
		"[!] Not walked, not in the mount table when the scan began: /media/late",
	} {
		if !strings.Contains(details, want) {
			t.Errorf("the report lacks %q:\n%s", want, details)
		}
	}
	for _, key := range []registry.FindingKey{ruleSetID, ruleWorldWritable, ruleUnowned} {
		got := conditions(r)[key]
		if got.Result != finding.ResultError || !strings.Contains(got.Reason, "2 filesystems beneath the scan root could not be judged") {
			t.Errorf("%s = %s (%s) with two filesystems unjudged, want an error naming them", key, got.Result, got.Reason)
		}
	}
}

// A mount table that could not be read leaves every rule with nothing found
// inconclusive, whether or not the walk met another filesystem.
func TestReportScanWithoutAMountTable(t *testing.T) {
	linux := registry.OSContext{Platform: registry.PlatformLinux, Families: []registry.Distro{registry.DistroGeneric}}
	r := newReport(checkIdentity{osCtx: linux})
	reportScan(r, fsScan{tableErr: os.ErrPermission, scanned: 1}, nil)
	if got := conditions(r)[ruleSetID]; got.Result != finding.ResultError || !strings.Contains(got.Reason, "mount table could not be read") {
		t.Errorf("setuid rule = %s (%s), want an error naming the mount table", got.Result, got.Reason)
	}
}

// The descent passes over a mount point the plan decided, without reading
// it, and records a directory on a filesystem the plan does not name.
func TestReadDirStopsAtMounts(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"kept", "planned"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, _, dev, ok := fileIdentity(info)
	if !ok {
		t.Fatal("no filesystem identity for the temporary directory")
	}

	w := &fsWalk{ids: newIdentityCache(), denied: &deniedJudge{}, plan: scanPlan{
		stops: map[string]struct{}{filepath.Join(dir, "planned"): {}},
		stray: leftUnlisted,
	}}
	here := treewalk.Dir[walkState]{Path: dir, State: walkState{dev: dev}}
	subdirs, found := w.readDir(context.Background(), here)
	if len(subdirs) != 1 || subdirs[0].Path != filepath.Join(dir, "kept") || found.scanned != 2 || len(found.left) != 0 {
		t.Errorf("read %d entries into %v and left %v, want kept and the file", found.scanned, subdirs, found.left)
	}
	if subdirs[0].State.dev != dev {
		t.Errorf("kept carries device %d, want its filesystem's %d", subdirs[0].State.dev, dev)
	}

	// Read as though it were on another filesystem, a directory the plan
	// does not name is one the scan must say it left out. The file is
	// classified all the same: an overlay gives its files the device of the
	// layer beneath, so a file's device marks no boundary.
	elsewhere := treewalk.Dir[walkState]{Path: dir, State: walkState{dev: dev + 1}}
	subdirs, found = w.readDir(context.Background(), elsewhere)
	if len(subdirs) != 0 || found.scanned != 1 || len(found.left) != 1 ||
		found.left[0].point != filepath.Join(dir, "kept") || found.left[0].reason != leftUnlisted {
		t.Errorf("read %d entries into %v and left %v, want kept left out as unlisted", found.scanned, subdirs, found.left)
	}
}

// A mount point the plan walks from is classified and handed to the walk as
// a directory; a file is the whole of its mount, and one that is gone is
// counted unreadable.
func TestEnterMountPoint(t *testing.T) {
	root := t.TempDir()
	point := filepath.Join(root, "a", "mnt")
	if err := os.MkdirAll(point, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "a", "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	w := &fsWalk{ids: newIdentityCache(), denied: &deniedJudge{}}
	var scan fsScan
	start, ok := w.enter(context.Background(), &scan, root, point)
	if !ok || start.Path != point || start.State.reach != reachNonRoot || scan.scanned != 1 {
		t.Errorf("enter(%s) = %+v, %v with %d scanned, want the directory, reachable, 1 scanned", point, start, ok, scan.scanned)
	}
	if _, ok := w.enter(context.Background(), &scan, root, file); ok || scan.scanned != 2 {
		t.Errorf("a file mount point was handed to the walk or not classified: %d scanned", scan.scanned)
	}
	if _, ok := w.enter(context.Background(), &scan, root, filepath.Join(root, "gone")); ok || scan.unreadable != 1 {
		t.Errorf("a missing mount point: %d unreadable, want 1", scan.unreadable)
	}
}
