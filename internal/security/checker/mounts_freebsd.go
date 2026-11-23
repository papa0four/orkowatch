//go:build freebsd

// internal/security/checker/mounts_freebsd.go

package checker

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The kernel's table of filesystem types and the flags it keeps for each,
// from sys/mount.h: struct xvfsconf is a pointer, the type name, three
// integers of which the last is the flags, and a pointer, with the padding
// the second pointer's alignment asks for.
const (
	vfsConfList = "vfs.conflist"

	vfcNetwork   = 0x00020000
	vfcSynthetic = 0x00080000
	vfcLoopback  = 0x00100000

	vfcNameSize  = 16
	vfcFieldSize = 4
	vfcPointer   = int(unsafe.Sizeof(uintptr(0)))
	vfcNameAt    = vfcPointer
	vfcFlagsAt   = vfcNameAt + vfcNameSize + 2*vfcFieldSize
	vfcSize      = (vfcFlagsAt+vfcFieldSize+vfcPointer-1)/vfcPointer*vfcPointer + vfcPointer

	fsidHalfBits = 32
)

// readMounts reads the mount table and judges each mount by the flags the
// kernel keeps for its filesystem type, so no type is named here. The mount
// flag MNT_LOCAL is not the judgment: procfs carries it.
func readMounts() (mounts []mount, judged bool, err error) {
	raw, err := unix.SysctlRaw(vfsConfList)
	if err != nil {
		return nil, true, fmt.Errorf("%s: %w", vfsConfList, err)
	}
	flags, err := parseVFSConf(raw)
	if err != nil {
		return nil, true, err
	}

	count, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		return nil, true, fmt.Errorf("getfsstat: %w", err)
	}
	table := make([]unix.Statfs_t, count)
	count, err = unix.Getfsstat(table, unix.MNT_NOWAIT)
	if err != nil {
		return nil, true, fmt.Errorf("getfsstat: %w", err)
	}

	mounts = make([]mount, 0, count)
	for i := range table[:count] {
		entry := &table[i]
		m := mount{
			point:  unix.ByteSliceToString(entry.Mntonname[:]),
			fstype: unix.ByteSliceToString(entry.Fstypename[:]),
			shows:  "/",
			fsid:   filesystemID(entry.Fsid),
		}
		m.kind = freebsdKind(m.fstype, flags)
		if m.kind == mountAlias {
			m.source = unix.ByteSliceToString(entry.Mntfromname[:])
		}
		m.hidden = hiddenMount(m)
		mounts = append(mounts, m)
	}
	return mounts, true, nil
}

// parseVFSConf returns the flags of each filesystem type in a vfs.conflist
// reading. A length that is not a whole number of records is refused rather
// than read at offsets that would then be wrong.
func parseVFSConf(raw []byte) (map[string]uint32, error) {
	if len(raw) == 0 || len(raw)%vfcSize != 0 {
		return nil, fmt.Errorf("%s: unexpected length %d", vfsConfList, len(raw))
	}
	flags := make(map[string]uint32, len(raw)/vfcSize)
	for ; len(raw) > 0; raw = raw[vfcSize:] {
		name := unix.ByteSliceToString(raw[vfcNameAt : vfcNameAt+vfcNameSize])
		flags[name] = binary.NativeEndian.Uint32(raw[vfcFlagsAt:])
	}
	return flags, nil
}

// freebsdKind judges a filesystem type by its kernel flags: synthetic data
// represents no real files, a network type may fetch its data from another
// host, and a loopback type shows files that lie elsewhere on this one. A
// type with none of the three holds its own files here. A type the table
// does not list is left unjudged.
func freebsdKind(fstype string, flags map[string]uint32) mountKind {
	typeFlags, listed := flags[fstype]
	switch {
	case !listed:
		return mountUnjudged
	case typeFlags&vfcSynthetic != 0:
		return mountPseudo
	case typeFlags&vfcNetwork != 0:
		return mountNetwork
	case typeFlags&vfcLoopback != 0:
		return mountAlias
	default:
		return mountLocal
	}
}

// hiddenMount reports whether the mount point no longer leads to the mount:
// another filesystem answers there, or the path is gone beneath a later
// mount. A network mount is not asked, since the question can wait on a
// server that does not answer.
func hiddenMount(m mount) bool {
	if m.kind == mountNetwork {
		return false
	}
	var at unix.Statfs_t
	err := unix.Statfs(m.point, &at)
	if err != nil {
		return errors.Is(err, unix.ENOENT)
	}
	return filesystemID(at.Fsid) != m.fsid
}

// filesystemID joins the two halves of a filesystem identifier, which no two
// mounted filesystems share.
func filesystemID(id unix.Fsid) uint64 {
	return uint64(uint32(id.Val[0]))<<fsidHalfBits | uint64(uint32(id.Val[1])) // #nosec G115 -- the halves are bit patterns, not quantities
}
