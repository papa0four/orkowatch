//go:build linux || freebsd

// internal/security/checker/reach_judge.go

// What a directory confers when its mode bits deny traversal, on the
// platforms whose access control lists are read: the POSIX.1e judgment and
// who holds root's group. Each platform supplies the read of the list, of
// supplementary membership and of which account sources it can list in full.

package checker

import (
	"context"
	"errors"
	"io/fs"
	"os/exec"
	"strings"
	"sync"

	"github.com/papa0four/orkowatch/internal/account"
)

// POSIX.1e entry tags and the execute permission. linux/posix_acl.h and
// FreeBSD's sys/acl.h give them the same values.
const (
	aclTagUser     = 0x02
	aclTagGroupObj = 0x04
	aclTagGroup    = 0x08
	aclTagMask     = 0x10

	aclPermExecute = 0x01

	nsswitchFile = "/etc/nsswitch.conf"
)

// errNoACL is the read of a directory that carries no access control list,
// which leaves its mode bits as the whole answer.
var errNoACL = errors.New("directory carries no access control list")

type (
	// deniedJudge decides what a directory confers when its mode bits deny
	// traversal. Whether root's group has another member is the same answer
	// for every directory, so it is asked once and kept; once makes that
	// true when several workers reach the question together.
	deniedJudge struct {
		once      sync.Once
		rootGroup reachability
	}

	// aclEntry is one entry of a POSIX.1e access ACL.
	aclEntry struct {
		tag  uint32
		perm uint32
		id   uint32
	}

	// nsswitchLine is one database line of nsswitch.conf: the database and
	// the sources it lists, in order.
	nsswitchLine struct {
		database string
		sources  []string
	}
)

// posixReach judges a directory by its mode bits and its POSIX.1e ACL.
// Without group-execute nothing can grant traversal, because the group bits
// of a directory carrying an ACL are the ACL mask and the mask caps every
// entry but the owner's and other's, so the ACL is not read. With it, the
// owning group is root's, and the answer rests on the ACL entries and on who
// belongs to that group. read reports errNoACL for a directory with no ACL.
func (j *deniedJudge) posixReach(ctx context.Context, mode fs.FileMode, read func() ([]aclEntry, error)) reachability {
	if mode.Perm()&bitGroupExecute == 0 {
		return reachRootOnly
	}

	entries, err := read()
	switch {
	case errors.Is(err, errNoACL):
		// The group bits belong to the owning group alone.
		return j.rootGroupReach(ctx)
	case err != nil:
		return reachUndetermined
	}

	return j.aclReach(ctx, entries)
}

// aclReach judges the entries of an ACL whose mask grants execute. A named
// user or group other than root's is reachable outright, over-approximating
// for groups the way traversableByNonRoot does; root's group, whether owning
// or named, defers to its membership.
func (j *deniedJudge) aclReach(ctx context.Context, entries []aclEntry) reachability {
	mask := uint32(aclPermExecute)
	for _, entry := range entries {
		if entry.tag == aclTagMask {
			mask = entry.perm
		}
	}

	var rootGroupGranted bool
	for _, entry := range entries {
		if entry.perm&mask&aclPermExecute == 0 {
			continue
		}
		switch entry.tag {
		case aclTagUser:
			if entry.id != rootUID {
				return reachNonRoot
			}
		case aclTagGroup:
			if entry.id != rootGID {
				return reachNonRoot
			}
			rootGroupGranted = true
		case aclTagGroupObj:
			rootGroupGranted = true
		}
	}

	if rootGroupGranted {
		return j.rootGroupReach(ctx)
	}
	return reachRootOnly
}

func (j *deniedJudge) rootGroupReach(ctx context.Context) reachability {
	j.once.Do(func() { j.rootGroup = rootGroupReach(ctx) })
	return j.rootGroup
}

// rootGroupReach reports what group-execute held by root's group confers.
// Any account other than root holding gid 0, as its primary group or among
// its supplementary groups, makes the directory reachable. Finding none
// proves root-only just when every configured account source can be
// enumerated; otherwise an account this host cannot list might hold the
// group, and the answer is undetermined.
func rootGroupReach(ctx context.Context) reachability {
	output, err := exec.CommandContext(ctx, account.GetentProgram, "passwd").Output() // #nosec G204 -- the program is the fixed path account.GetentProgram and the argument a literal
	if err != nil {
		return reachUndetermined
	}

	var names []string
	for _, a := range account.ParseAll(output) {
		switch {
		case a.UID == rootUID:
		case a.GID == rootGID:
			return reachNonRoot
		default:
			names = append(names, a.Name)
		}
	}

	member, err := anyInRootGroup(ctx, names)
	switch {
	case err != nil:
		return reachUndetermined
	case member:
		return reachNonRoot
	case !accountSourcesEnumerable():
		return reachUndetermined
	default:
		return reachRootOnly
	}
}

// parseNsswitch returns the database lines of nsswitch.conf. Bracketed
// action items such as [NOTFOUND=return] are not sources and are left out.
func parseNsswitch(data []byte) []nsswitchLine {
	var lines []nsswitchLine
	for _, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		database, ok := strings.CutSuffix(fields[0], ":")
		if !ok {
			continue
		}

		entry := nsswitchLine{database: database}
		var inAction bool
		for _, source := range fields[1:] {
			if strings.HasPrefix(source, "[") {
				inAction = true
			}
			if inAction {
				inAction = !strings.HasSuffix(source, "]")
				continue
			}
			entry.sources = append(entry.sources, source)
		}
		lines = append(lines, entry)
	}
	return lines
}
