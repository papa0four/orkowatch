//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/security/checker/scan_mounts.go

// Which filesystems beneath a scan root the permissions scan walks. Each
// platform reads its mount table and judges every mount; the plan made from
// those judgements is the same on all of them.

package checker

import (
	"cmp"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

type (
	// mount is one mount of the host's mount table as its platform judged it.
	// fsid is equal for two mounts of one filesystem and for no others. shows
	// is the directory of that filesystem the mount shows, "/" for all of it.
	// source is set on a mountAlias alone: the path whose files it shows.
	mount struct {
		point  string
		fstype string
		shows  string
		source string
		fsid   uint64
		kind   mountKind
		hidden bool
	}

	// mountKind is what a platform judged a mount's filesystem to be.
	mountKind uint8

	// leftMount is a mount the scan did not walk, or a directory where a
	// filesystem the plan does not know begins.
	leftMount struct {
		point  string
		fstype string
		detail string
		reason leftReason
	}

	// leftReason is why a mount was not walked. The order is the order the
	// report states them in.
	leftReason uint8

	// scanPlan is what a scan of one root covers beyond the root's own
	// filesystem: the mount points it also walks from, the mount points a
	// descent stops at because the plan has already decided them, and the
	// mounts it leaves out.
	scanPlan struct {
		starts []string
		stops  map[string]struct{}
		left   []leftMount
		stray  leftReason
	}
)

const (
	// mountUnjudged is the zero value deliberately: a mount no rule spoke
	// for is left out and said to be, never walked by default.
	mountUnjudged mountKind = iota
	mountLocal
	mountAlias
	mountPseudo
	mountNetwork
	mountFUSE
)

const (
	leftPseudo leftReason = iota
	leftNetwork
	leftFUSE
	leftSame
	leftHidden
	leftUnjudgedPlatform
	leftUnjudged
	leftUnlisted
	leftNoTable
)

// leftReasons words each reason as the report states it, and says whether a
// mount left out for it means the scan did not see everything it should
// have. A pseudo-filesystem left out is the scan working as meant; a
// filesystem nothing could judge is a gap.
var leftReasons = map[leftReason]struct {
	text string
	gap  bool
}{
	leftPseudo:           {"pseudo-filesystem", false},
	leftNetwork:          {"network filesystem", false},
	leftFUSE:             {"FUSE filesystem", false},
	leftSame:             {"same filesystem as another path", false},
	leftHidden:           {"hidden beneath another mount", false},
	leftUnjudgedPlatform: {"filesystems are not judged on this platform", false},
	leftUnjudged:         {"no judgement for the filesystem type", true},
	leftUnlisted:         {"not in the mount table when the scan began", true},
	leftNoTable:          {"the mount table could not be read", true},
}

// reason is why a mount of this kind is left out. A kind that is walked has
// none and is never asked.
func (k mountKind) reason() leftReason {
	switch k {
	case mountPseudo:
		return leftPseudo
	case mountNetwork:
		return leftNetwork
	case mountFUSE:
		return leftFUSE
	default:
		return leftUnjudged
	}
}

// planScan decides every mount beneath root. A local filesystem is walked
// from its mount point unless a mount already walked shows the same files,
// so a filesystem mounted twice or bound elsewhere is walked once. Mounts are
// taken in order of how much of their filesystem they show, the shortest
// path first among equals, which makes the one walked the same from run to
// run. The descent stops at
// every mount point: a mount is entered from the plan or not at all.
func planScan(root string, mounts []mount) scanPlan {
	plan := scanPlan{stops: make(map[string]struct{})}

	walked := []mount{rootMount(root, mounts)}
	entered := map[string]bool{root: true}
	var local, aliases []mount
	for _, m := range mounts {
		if m.point == root || !pathWithin(m.point, root) {
			continue
		}
		if m.hidden {
			plan.leave(m, leftHidden, "")
			continue
		}
		plan.stops[m.point] = struct{}{}
		switch m.kind {
		case mountLocal:
			local = append(local, m)
		case mountAlias:
			aliases = append(aliases, m)
		default:
			plan.leave(m, m.kind.reason(), "")
		}
	}

	byExtent := func(a, b mount) int {
		return cmp.Or(cmp.Compare(len(a.shows), len(b.shows)), cmp.Compare(len(a.point), len(b.point)),
			strings.Compare(a.point, b.point))
	}
	slices.SortFunc(local, byExtent)
	slices.SortFunc(aliases, byExtent)

	for _, m := range local {
		entered[m.point] = true
		if at, ok := plan.shownBy(walked, m); ok {
			plan.leave(m, leftSame, "walked at "+at)
			continue
		}
		walked = append(walked, m)
		plan.starts = append(plan.starts, m.point)
	}

	// An alias shows files that lie at its source. Where the scan enters the
	// filesystem the source is on, they are judged there; otherwise the
	// alias is the only way to them and is walked like a local filesystem.
	for _, m := range aliases {
		shown := pathWithin(m.source, root) && entered[plan.mountOver(root, m.source)]
		entered[m.point] = true
		if shown {
			plan.leave(m, leftSame, "shows "+m.source)
			continue
		}
		plan.starts = append(plan.starts, m.point)
	}

	slices.Sort(plan.starts)
	return plan
}

// rootMount is the scan root as a mount: the part of its filesystem it
// shows, worked out from the mount it lies in. With no mount table it shows
// a filesystem no other mount can be compared against.
func rootMount(root string, mounts []mount) mount {
	start := mount{point: root, shows: "/", kind: mountLocal}
	var over mount
	for _, m := range mounts {
		if !m.hidden && pathWithin(root, m.point) && len(m.point) >= len(over.point) {
			over = m
		}
	}
	if over.point == "" {
		return start
	}
	start.fsid = over.fsid
	if rel, err := filepath.Rel(over.point, root); err == nil {
		start.shows = filepath.Join(over.shows, rel)
	}
	return start
}

// shownBy reports the mount point of a walked mount whose walk reads the
// directory m shows. That takes more than one filesystem and one directory
// beneath the other: the walk must also arrive there, which it does not when
// a mount point lies on the way, since the descent stops at each.
func (p *scanPlan) shownBy(walked []mount, m mount) (string, bool) {
	for _, w := range walked {
		if w.fsid != m.fsid || !pathWithin(m.shows, w.shows) {
			continue
		}
		rel, err := filepath.Rel(w.shows, m.shows)
		if err != nil {
			continue
		}
		if p.mountOver(w.point, filepath.Join(w.point, rel)) == w.point {
			return w.point, true
		}
	}
	return "", false
}

// mountOver returns the deepest mount point at or above path and beneath
// from, or from itself when the way down to path crosses none.
func (p *scanPlan) mountOver(from, path string) string {
	over := from
	for stop := range p.stops {
		if stop != from && pathWithin(stop, from) && pathWithin(path, stop) && len(stop) > len(over) {
			over = stop
		}
	}
	return over
}

// leave records a mount the scan does not walk.
func (p *scanPlan) leave(m mount, reason leftReason, detail string) {
	p.left = append(p.left, leftMount{point: m.point, fstype: m.fstype, detail: detail, reason: reason})
}

// String names the mount with what is known of it: its type, and for a
// mount another path stands in for, which one.
func (l leftMount) String() string {
	var known []string
	if l.fstype != "" {
		known = append(known, l.fstype)
	}
	if l.detail != "" {
		known = append(known, l.detail)
	}
	if len(known) == 0 {
		return l.point
	}
	return fmt.Sprintf("%s (%s)", l.point, strings.Join(known, ", "))
}

// reportLeft states each reason once, followed by the mounts left out for
// it, and returns what a rule with nothing found must say when some of them
// are gaps in what the scan saw. It returns empty when none are.
func reportLeft(r *report, left []leftMount) string {
	slices.SortFunc(left, func(a, b leftMount) int {
		return cmp.Or(cmp.Compare(a.reason, b.reason), strings.Compare(a.point, b.point))
	})

	var gaps int
	for len(left) > 0 {
		reason := left[0].reason
		var names []string
		for len(left) > 0 && left[0].reason == reason {
			names = append(names, left[0].String())
			left = left[1:]
		}

		symbol := finding.SymbolInfo
		if leftReasons[reason].gap {
			symbol = finding.SymbolWarning
			gaps += len(names)
		}
		r.note(symbol, "Not walked, %s: %s", leftReasons[reason].text, strings.Join(names, ", "))
	}

	if gaps == 0 {
		return ""
	}
	return fmt.Sprintf("%d filesystems beneath the scan root could not be judged and went unscanned", gaps)
}
