//go:build linux

// internal/security/checker/mounts_linux.go

package checker

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/papa0four/orkowatch/internal/fspath"
)

// Where the kernel lists the mounts of this process's namespace and the
// filesystem types it supports, and the layout of a mountinfo line as proc(5)
// gives it: fixed fields, then optional ones up to a lone hyphen, then the
// filesystem type.
const (
	mountInfoFile   = "/proc/self/mountinfo"
	filesystemsFile = "/proc/filesystems"

	mountInfoID       = 0
	mountInfoParent   = 1
	mountInfoDevice   = 2
	mountInfoRoot     = 3
	mountInfoPoint    = 4
	mountInfoOptional = 6
	mountInfoEnd      = "-"

	octalEscape = 3
	octalBase   = 8
	byteBits    = 8
	deviceBits  = 32
	decimalBase = 10
)

// nodevKinds judges the filesystem types that need no block device, which is
// all the kernel says of them: a memory filesystem, a pseudo-filesystem and a
// network filesystem are alike there. A type that needs a block device is
// local on the kernel's word and is not listed. tmpfs, devtmpfs, rootfs,
// overlay, 9p, FUSE and the pseudo-filesystems proc, sysfs, devpts, cgroup2,
// binfmt_misc, hugetlbfs, mqueue, debugfs, tracefs and fusectl were mounted
// on the Ubuntu host this was written against; the other pseudo-filesystems
// are named by its /proc/filesystems. nfs, nfs4, cifs, smb3 and zfs were not
// on that host: the names are the ones their sources register, fs/nfs and
// fs/smb/client in the kernel and zpl_super.c in OpenZFS.
//
// fuse is every FUSE mount but fuseblk, which needs a block device. Whether
// one is local cannot be read from its type, so none is walked.
var nodevKinds = map[string]mountKind{
	"tmpfs":    mountLocal,
	"devtmpfs": mountLocal,
	"ramfs":    mountLocal,
	"rootfs":   mountLocal,
	"overlay":  mountLocal,
	"zfs":      mountLocal,

	"proc":        mountPseudo,
	"sysfs":       mountPseudo,
	"devpts":      mountPseudo,
	"cgroup":      mountPseudo,
	"cgroup2":     mountPseudo,
	"cpuset":      mountPseudo,
	"binfmt_misc": mountPseudo,
	"hugetlbfs":   mountPseudo,
	"mqueue":      mountPseudo,
	"debugfs":     mountPseudo,
	"tracefs":     mountPseudo,
	"fusectl":     mountPseudo,
	"configfs":    mountPseudo,
	"securityfs":  mountPseudo,
	"bpf":         mountPseudo,
	"pstore":      mountPseudo,
	"efivarfs":    mountPseudo,
	"selinuxfs":   mountPseudo,
	"autofs":      mountPseudo,

	"9p":       mountNetwork,
	"virtiofs": mountNetwork,
	"nfs":      mountNetwork,
	"nfs4":     mountNetwork,
	"cifs":     mountNetwork,
	"smb3":     mountNetwork,

	"fuse": mountFUSE,
}

// mountInfoLine is one mount with its place in the mount tree, which is what
// says whether a later mount hides it.
type mountInfoLine struct {
	mount
	id     int
	parent int
}

// readMounts reads the mounts of this process's namespace and judges each by
// its filesystem type.
func readMounts() (mounts []mount, judged bool, err error) {
	types, err := os.ReadFile(filesystemsFile)
	if err != nil {
		return nil, true, err
	}
	table, err := os.ReadFile(mountInfoFile)
	if err != nil {
		return nil, true, err
	}
	mounts, err = parseMountInfo(string(table), blockBacked(string(types)))
	return mounts, true, err
}

// blockBacked returns the filesystem types /proc/filesystems lists without
// nodev, which proc(5) says are the ones that need a block device.
func blockBacked(filesystems string) map[string]bool {
	backed := make(map[string]bool)
	for _, line := range strings.Split(filesystems, "\n") {
		if fields := strings.Fields(line); len(fields) == 1 {
			backed[fields[0]] = true
		}
	}
	return backed
}

// linuxKind judges a filesystem type, written type or type.subtype. The
// subtype names the program behind a FUSE mount and changes nothing here.
func linuxKind(fstype string, backed map[string]bool) mountKind {
	base, _, _ := strings.Cut(fstype, ".")
	if backed[base] {
		return mountLocal
	}
	return nodevKinds[base]
}

// parseMountInfo reads a mountinfo table. A line it cannot read fails the
// whole table rather than dropping a mount the scan would then walk into
// unjudged.
func parseMountInfo(table string, backed map[string]bool) ([]mount, error) {
	var lines []mountInfoLine
	for _, text := range strings.Split(table, "\n") {
		if strings.TrimSpace(text) == "" {
			continue
		}
		line, err := parseMountInfoLine(text, backed)
		if err != nil {
			return nil, err
		}
		lines = append(lines, line)
	}

	mounts := make([]mount, 0, len(lines))
	for _, line := range lines {
		line.hidden = hiddenMount(line, lines)
		mounts = append(mounts, line.mount)
	}
	return mounts, nil
}

// parseMountInfoLine reads one mount. The device is what stat reports for
// files on the filesystem, so two mounts of one filesystem share it, and the
// root is the directory of the filesystem the mount shows.
func parseMountInfoLine(text string, backed map[string]bool) (mountInfoLine, error) {
	malformed := func(what string) (mountInfoLine, error) {
		return mountInfoLine{}, fmt.Errorf("mountinfo: %s in %q", what, text)
	}

	fields := strings.Fields(text)
	end := mountInfoOptional
	for end < len(fields) && fields[end] != mountInfoEnd {
		end++
	}
	if end+1 >= len(fields) {
		return malformed("no filesystem type")
	}

	id, err := strconv.Atoi(fields[mountInfoID])
	if err != nil {
		return malformed("no mount identifier")
	}
	parent, err := strconv.Atoi(fields[mountInfoParent])
	if err != nil {
		return malformed("no parent identifier")
	}
	major, minor, ok := strings.Cut(fields[mountInfoDevice], ":")
	high, errHigh := strconv.ParseUint(major, decimalBase, deviceBits)
	low, errLow := strconv.ParseUint(minor, decimalBase, deviceBits)
	if !ok || errHigh != nil || errLow != nil {
		return malformed("no device")
	}

	fstype := fields[end+1]
	return mountInfoLine{
		id:     id,
		parent: parent,
		mount: mount{
			point:  unescapeMountInfo(fields[mountInfoPoint]),
			fstype: fstype,
			shows:  unescapeMountInfo(fields[mountInfoRoot]),
			fsid:   high<<deviceBits | low,
			kind:   linuxKind(fstype, backed),
		},
	}, nil
}

// unescapeMountInfo restores the characters the kernel writes as a backslash
// and three octal digits so that a path holds no field separator.
func unescapeMountInfo(field string) string {
	if !strings.Contains(field, `\`) {
		return field
	}
	var path strings.Builder
	for i := 0; i < len(field); i++ {
		if field[i] == '\\' && i+octalEscape < len(field) {
			if code, err := strconv.ParseUint(field[i+1:i+1+octalEscape], octalBase, byteBits); err == nil {
				path.WriteByte(byte(code))
				i += octalEscape
				continue
			}
		}
		path.WriteByte(field[i])
	}
	return path.String()
}

// hiddenMount reports whether the path a mount was made at no longer leads
// to it. A mount made over another's mount point becomes its child at the
// same path and hides it. A mount made over a directory above another's
// mount point stays its sibling and hides it too, and whatever hides a mount
// hides the mounts beneath it.
func hiddenMount(line mountInfoLine, lines []mountInfoLine) bool {
	for _, other := range lines {
		if other.parent == line.id && other.id != line.id && other.point == line.point {
			return true
		}
	}
	return coveredMount(line, lines, len(lines))
}

// coveredMount reports whether a sibling mounted above line's mount point,
// or above any mount line lies in, covers the path to it. depth bounds the
// climb so a table whose parents form a cycle cannot hold it.
func coveredMount(line mountInfoLine, lines []mountInfoLine, depth int) bool {
	if depth == 0 {
		return false
	}
	for _, other := range lines {
		switch {
		case other.id == line.id:
		case other.parent == line.parent && other.point != line.point && fspath.Within(line.point, other.point):
			return true
		case other.id == line.parent && other.id != other.parent:
			if coveredMount(other, lines, depth-1) {
				return true
			}
		}
	}
	return false
}
