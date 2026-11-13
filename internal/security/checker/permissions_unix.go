//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/security/checker/permissions_unix.go

package checker

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/security/types"
)

// Expected file and directory permission modes: the shared vocabulary every
// platform's critical paths draw from, declared together so a platform picks an
// expectation rather than inventing one inline. Not every value is referenced on
// every platform. permPrivateDir is used by Linux and the BSDs, permReadOnlyDir
// only by Linux, and a constant no build references compiles away.
const (
	permStandardFile        os.FileMode = 0644
	permOwnerWriteGroupRead os.FileMode = 0640
	permSudoers             os.FileMode = 0440
	permOwnerReadWrite      os.FileMode = 0600
	permStandardDir         os.FileMode = 0755
	permGroupWritableDir    os.FileMode = 0775
	permPrivateDir          os.FileMode = 0700
	permReadOnlyDir         os.FileMode = 0555

	// Permission bit masks
	bitWorldWritable os.FileMode = 0002
	bitOwnerExecute  os.FileMode = 0100
	bitGroupExecute  os.FileMode = 0010
	bitOtherExecute  os.FileMode = 0001

	// Account databases consulted before the name service, and the
	// colon-delimited field holding each numeric identifier.
	unixPasswdFile = "/etc/passwd"
	unixGroupFile  = "/etc/group"
	unixIDField    = 2

	identityKindUser  identityKind = "user"
	identityKindGroup identityKind = "group"
)

type (
	// UnixPermissionChecker implements PermissionChecker for Unix-like
	// systems. The platform supplies its own critical paths and name service
	// under its build constraint.
	UnixPermissionChecker struct {
		checkIdentity
		paths    []criticalPath
		scanRoot string
	}

	// criticalPath is a path whose mode must not exceed expected and which
	// every supported distribution ships owned by root. expected is the most
	// permissive acceptable mode rather than the mode any one distribution
	// ships, because the test admits anything stricter: /etc/shadow is 0640
	// root:shadow on Debian family and 0000 root:root on RHEL family, and
	// one expectation of 0640 is correct for both. Ownership carries the
	// difference a mode cannot express, which is why it is checked too.
	criticalPath struct {
		path        string
		description string
		expected    os.FileMode
	}

	// identityCache reports whether numeric owners and groups resolve to a real
	// principal, memoizing by identifier. A filesystem holds orders of magnitude
	// more entries than distinct identifiers, so resolution collapses from one
	// lookup per file to one per identifier.
	identityCache struct {
		users  map[uint32]bool
		groups map[uint32]bool
	}

	// fsScan is the outcome of one filesystem traversal.
	fsScan struct {
		suid       []scanEntry
		worldWrite []scanEntry
		unowned    []scanEntry
		unreadable int
	}

	// scanEntry is one entry the traversal recorded, kept as the facts that
	// were observed rather than as report text so that rendering happens in
	// one place.
	scanEntry struct {
		path       string
		mode       fs.FileMode
		uid        uint32
		gid        uint32
		userKnown  bool
		groupKnown bool
		reach      reachability
	}

	// fsWalk carries the state one filesystem traversal accumulates. rootDev
	// bounds the walk to the filesystem the root lives on, reach is the chain
	// of directories currently open above the entry being visited, and denied
	// is the platform's judgment of a directory whose mode bits deny traversal.
	fsWalk struct {
		ids     *identityCache
		rootDev uint64
		reach   []reachFrame
		denied  deniedJudge
		scan    fsScan
	}

	// reachFrame is one open directory and the reachability it confers on its
	// contents. WalkDir visits a directory before its contents and keeps a
	// subtree contiguous, so a stack bounded by tree depth tracks the chain
	// where a map would be bounded by directory count.
	reachFrame struct {
		dir   string
		reach reachability
	}

	// reachability is whether a principal other than root can traverse to an
	// entry. The zero value is reachNonRoot so an entry the walk failed to
	// judge is over-reported rather than quietly excused. Values are ordered
	// from widest to narrowest, so the narrower of two is the greater.
	reachability uint8

	// identityKind selects which account database a lookup consults.
	identityKind string
)

const (
	// reachNonRoot means some principal other than root can traverse every
	// directory leading to the entry. It is the zero value deliberately: a
	// path the walk did not judge is reported as reachable, because naming a
	// reachable entry unreachable would hide an exposure while the reverse
	// only adds noise.
	reachNonRoot reachability = iota

	// reachUnsupported means mode bits deny traversal on a platform whose
	// access control lists this checker does not read yet, so nothing
	// narrower than reachable is asserted there.
	reachUnsupported

	// reachUndetermined means mode bits deny traversal and what could grant
	// it anyway, an access control list or membership of root's group, could
	// not be read or enumerated.
	reachUndetermined

	// reachRootOnly means no principal other than root can traverse the
	// chain: mode bits deny it, no access control list grants it, and root's
	// group has no other member.
	reachRootOnly
)

// newIdentityCache seeds the cache from the local account databases. Anything
// they declare is known without consulting the name service.
func newIdentityCache() *identityCache {
	return &identityCache{
		users:  localIDs(unixPasswdFile),
		groups: localIDs(unixGroupFile),
	}
}

// localIDs returns the numeric identifiers declared by a colon-delimited
// account database. An unreadable file yields an empty set, which is safe:
// every identifier then falls through to the name service
func localIDs(path string) map[uint32]bool {
	ids := make(map[uint32]bool)
	data, err := os.ReadFile(path) // #nosec G304 -- path is a package constant
	if err != nil {
		return ids
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) <= unixIDField {
			continue
		}
		if id, ok := parseUnixID(fields[unixIDField]); ok {
			ids[id] = true
		}
	}
	return ids
}

// resolution reports separately whether the owner and the group map to a known
// principal. Both are always looked up rather than short-circuiting on the
// first failure, because an entry owned by root whose group is a container's
// is not an entry with no owner, and saying so requires knowing which one
// failed. The extra lookups are bounded by distinct indentifiers rather than by
// entries because the cache memoizes per identifier.
func (c *identityCache) resolution(ctx context.Context, uid, gid uint32) (userKnown, groupKnown bool) {
	userKnown = c.known(ctx, c.users, identityKindUser, uid)
	groupKnown = c.known(ctx, c.groups, identityKindGroup, gid)
	return userKnown, groupKnown
}

// known consults the cache, falling back to the name service for identifiers
// the local database does not declare. Directory-provided accounts exist only
// in the name service, so a local miss alone is not evidence of an orphan.
func (c *identityCache) known(ctx context.Context, cache map[uint32]bool, kind identityKind, id uint32) bool {
	if resolved, seen := cache[id]; seen {
		return resolved
	}
	resolved := nameServiceKnows(ctx, kind, id)
	cache[id] = resolved
	return resolved
}

// NewPermissionChecker returns the file permission checker for Unix-like
// hosts. scanRoot narrows the filesystem scan to one tree; empty means the
// whole filesystem, plus the critical paths.
func NewPermissionChecker(osCtx registry.OSContext, scanRoot string) *UnixPermissionChecker {
	return &UnixPermissionChecker{
		checkIdentity: checkIdentity{
			domain:   "File Permissions Security",
			analyzes: "file and directory permissions",
			osCtx:    osCtx,
		},
		paths:    append(commonCriticalPaths(), platformCriticalPaths()...),
		scanRoot: scanRoot,
	}
}

// The rules this check concludes: two judged on the critical paths, three on
// every entry the traversal visits.
const (
	ruleExcessMode    registry.FindingKey = "permissions.path_exceeds_expected_mode"
	ruleNotRootOwned  registry.FindingKey = "permissions.critical_path_not_root_owned"
	ruleSetID         registry.FindingKey = "permissions.suid_sgid_binary"
	ruleWorldWritable registry.FindingKey = "permissions.world_writable_file"
	ruleUnowned       registry.FindingKey = "permissions.unowned_file"
)

// Check implements PermissionChecker interface for Unix systems
func (p *UnixPermissionChecker) Check(ctx context.Context) types.AuditResult {
	r := newReport(p.checkIdentity)

	root, err := p.effectiveRoot()
	if err != nil {
		r.inconclusive(types.ResultError, fmt.Sprintf("scan root could not be resolved: %v", err),
			ruleExcessMode, ruleNotRootOwned, ruleSetID, ruleWorldWritable, ruleUnowned)
		return r.finish()
	}

	r.note(types.SymbolInfo, "Scanning %s", root)
	p.checkCriticalPaths(root, r)

	scan, err := p.scanFilesystem(ctx, root)
	reportScan(r, scan, err)

	return r.finish()
}

// effectiveRoot resolves the scan root to a real path: the operator's when one
// was supplied, the filesystem root otherwise. Symlinks are evaluated because
// the traversal and the critical-path scope both compare against this value,
// and filepath.WalkDir does not follow a symlinked root, so an unresolved one
// would scan a single entry instead of the tree it names.
func (p *UnixPermissionChecker) effectiveRoot() (string, error) {
	root := p.scanRoot
	if root == "" {
		root = "/"
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve scan root %s: %w", root, err)
	}
	return resolved, nil
}

// checkCriticalPaths evaluates every critical path lying at or beneath root.
// A supplied scan root narrows which paths are in scope; it never removes the
// expectation from a path that is in scope, because a mode and ownership
// expectation is a property of the path rather than of how the run was
// invoked. With no critical path in scope the two rules have nothing to
// apply to.
func (p *UnixPermissionChecker) checkCriticalPaths(root string, r *report) {
	var checked int
	for _, cpath := range p.paths {
		if !pathWithin(cpath.path, root) {
			continue
		}
		checked++
		checkCriticalPath(cpath, r)
	}

	if checked == 0 {
		r.inconclusive(types.ResultNotApplicable, "no critical system paths lie within "+root,
			ruleExcessMode, ruleNotRootOwned)
		return
	}
	r.pass(ruleExcessMode, ruleNotRootOwned)
}

// pathWithin reports whether target lies at or beneath base, comparing on path
// boundaries so a sibling is not mistaken for a child.
func pathWithin(target, base string) bool {
	if target == base {
		return true
	}
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// commonCriticalPaths lists the paths every Unix-like platform is expected
// to protect; platformCriticalPaths adds the platform's own.
func commonCriticalPaths() []criticalPath {
	return []criticalPath{
		{"/etc/passwd", "Password file", permStandardFile},
		{"/etc/shadow", "Shadow password file", permOwnerWriteGroupRead},
		{"/etc/group", "Group file", permStandardFile},
		{"/etc/sudoers", "Sudo configuration", permSudoers},
		{"/etc/ssh/sshd_config", "SSH daemon configuration", permOwnerReadWrite},
		{"/var/log", "Log directory", permGroupWritableDir},
		{"/home", "User home directories", permStandardDir},
	}
}

// checkCriticalPath records every way cp departs from what a critical system
// path must be. Both conditions are evaluated: a path can be both too
// permissive and wrongly owned, and recording only the first would hide the
// second.
//
// The mode test is a bitmask rather than a numeric comparison: a mode is too
// permissive when it sets any bit the expectation does not, which a
// greater-than test misses whenever the extra access is numerically smaller,
// as 0044 is against an expected 0600. A stricter mode is never a finding.
// Ownership is what makes a permissive-looking mode safe or unsafe:
// /etc/shadow at 0640 is the Debian design when root owns it and an exposure
// when an unprivileged account does.
func checkCriticalPath(cp criticalPath, r *report) {
	info, err := os.Stat(cp.path)
	switch {
	case os.IsNotExist(err):
		r.note(types.SymbolInfo, "Path does not exist: %s", cp.path)
		return
	case err != nil:
		r.inconclusive(types.ResultError, fmt.Sprintf("%s could not be checked: %v", cp.path, err),
			ruleExcessMode, ruleNotRootOwned)
		return
	}

	mode := info.Mode()
	modeOK := mode.Perm()&^cp.expected == 0
	if !modeOK {
		r.observed(ruleExcessMode, evidence(kindFile, cp.path,
			"description", cp.description,
			"mode", formatMode(mode),
			"expected", formatMode(cp.expected)))
	}

	uid, _, _, ok := fileIdentity(info)
	switch {
	case !ok:
		r.inconclusive(types.ResultError, cp.path+" ownership could not be determined", ruleNotRootOwned)
	case uid != rootUID:
		r.observed(ruleNotRootOwned, evidence(kindFile, cp.path,
			"description", cp.description,
			"uid", strconv.FormatUint(uint64(uid), decimalBase),
			"expected", "root"))
	case modeOK:
		r.note(types.SymbolOK, "%s has correct permissions and ownership: %s root", cp.path, formatMode(mode))
	}
}

// scanFilesystem walks the effective root once, collecting setuid, group- and
// world-writable, and unowned entries together. Identity lookups are cached
// per identifier rather than performed per entry, which is what makes a single
// pass cheaper than the three it replaces. The walk stays on the root's
// filesystem: pseudo-filesystems and network mounts are out of scope and can
// be pathologically slow to traverse.
func (p *UnixPermissionChecker) scanFilesystem(ctx context.Context, root string) (fsScan, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return fsScan{}, fmt.Errorf("stat scan root %s: %w", root, err)
	}
	_, _, rootDev, ok := fileIdentity(rootInfo)
	if !ok {
		return fsScan{}, fmt.Errorf("stat scan root %s: no filesystem identity", root)
	}

	w := fsWalk{ids: newIdentityCache(), rootDev: rootDev}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return w.visit(ctx, path, d, err)
	})

	return w.scan, err
}

// visit handles one traversal entry: an entry that cannot be read or
// identified is counted, an entry on another filesystem is skipped along
// with its subtree, and everything else is classified.
func (w *fsWalk) visit(ctx context.Context, path string, d fs.DirEntry, err error) error {
	if err != nil {
		w.scan.unreadable++
		if d != nil && d.IsDir() {
			return fs.SkipDir
		}
		return nil
	}

	info, err := d.Info()
	if err != nil {
		w.scan.unreadable++
		return nil
	}

	uid, gid, dev, ok := fileIdentity(info)
	if !ok {
		w.scan.unreadable++
		return nil
	}
	if dev != w.rootDev {
		if d.IsDir() {
			return fs.SkipDir
		}
		return nil
	}

	reach := w.reachOf(path)
	if d.IsDir() {
		w.descend(ctx, path, reach, info.Mode(), uid, gid)
	}

	w.classify(ctx, path, info, uid, gid, reach)
	return nil
}

// classify records the entry under each category it belongs to. Setuid and
// world-writable apply to regular files only; ownership applies to every
// entry.
func (w *fsWalk) classify(ctx context.Context, path string, info fs.FileInfo, uid, gid uint32, reach reachability) {
	mode := info.Mode()
	userKnown, groupKnown := w.ids.resolution(ctx, uid, gid)
	entry := scanEntry{
		path:       path,
		mode:       mode,
		uid:        uid,
		gid:        gid,
		userKnown:  userKnown,
		groupKnown: groupKnown,
		reach:      reach,
	}

	if mode.IsRegular() {
		if mode&(os.ModeSetuid|os.ModeSetgid) != 0 {
			w.scan.suid = append(w.scan.suid, entry)
		}
		if mode.Perm()&bitWorldWritable != 0 {
			w.scan.worldWrite = append(w.scan.worldWrite, entry)
		}
	}

	if !userKnown || !groupKnown {
		w.scan.unowned = append(w.scan.unowned, entry)
	}
}

// reachOf returns what the directory chain above path confers, discarding the
// frames the walk has left. An entry is only as reachable as the directories
// that must be traversed to arrive at it, whatever its own mode says.
func (w *fsWalk) reachOf(path string) reachability {
	for len(w.reach) > 0 {
		top := w.reach[len(w.reach)-1]
		if path != top.dir && pathWithin(path, top.dir) {
			return top.reach
		}
		w.reach = w.reach[:len(w.reach)-1]
	}
	return reachNonRoot
}

// descend records what dir confers on its contents. A directory only root can
// traverse makes everything beneath it root-only regardless of the modes those
// entries carry, so reachability only ever narrows on the way down. The
// platform is asked only about a directory mode bits deny and whose chain is
// not already root-only, which keeps that cost off every other directory.
func (w *fsWalk) descend(ctx context.Context, dir string, parent reachability, mode fs.FileMode, uid, gid uint32) {
	conferred := parent
	if parent != reachRootOnly && !traversableByNonRoot(mode, uid, gid) {
		conferred = max(parent, w.denied.reach(ctx, dir, mode))
	}
	w.reach = append(w.reach, reachFrame{dir: dir, reach: conferred})
}

// traversableByNonRoot reports whether mode bits alone let a principal other
// than root traverse a directory with this mode and ownership. It
// over-approximates deliberately: group-execute counts whenever the group is
// not root's, without asking whether that group has members, because calling
// a root-only path reachable only adds noise while the reverse hides an
// exposure. A false answer is not yet a verdict: deniedJudge decides what the
// bits cannot, including the case left open here, group-execute held by root's
// own group.
func traversableByNonRoot(mode fs.FileMode, uid, gid uint32) bool {
	perm := mode.Perm()
	switch {
	case perm&bitOtherExecute != 0:
		return true
	case perm&bitGroupExecute != 0 && gid != rootGID:
		return true
	case perm&bitOwnerExecute != 0 && uid != rootUID:
		return true
	default:
		return false
	}
}

// label names how far an entry whose chain mode bits deny can be reached, so
// an operator can tell an exposure from an entry only root could ever have
// touched, and either from one the checker could not decide. A reachable
// entry carries no label, because the common case should not add a fact to
// every entry.
func (r reachability) label() string {
	switch r {
	case reachRootOnly:
		return "root-only"
	case reachUndetermined:
		return "undetermined"
	case reachUnsupported:
		return "not evaluated on this platform"
	default:
		return ""
	}
}

// fileIdentity returns the numeric owner, group, and device of info, and
// reports whether the platform supplied them.
func fileIdentity(info fs.FileInfo) (uid, gid uint32, dev uint64, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, false
	}
	return st.Uid, st.Gid, uint64(st.Dev), true
}

// evidence returns the entry as the facts observed about it. The identifiers
// stay numeric deliberately: when one of them failed to resolve it is the
// value that failed, and a name would be misleading.
func (e scanEntry) evidence() types.Evidence {
	return evidence(kindFile, e.path,
		"mode", formatMode(e.mode),
		"uid", strconv.FormatUint(uint64(e.uid), decimalBase),
		"gid", strconv.FormatUint(uint64(e.gid), decimalBase),
		"unresolved", e.unresolved(),
		"reach", e.reach.label())
}

// unresolved names which identifiers the name service could not account for,
// so a root-owned entry carrying a group that only exists inside a container
// is not reported as an entry with no owner at all. An entry whose owner and
// group both resolved is named by neither, rather than by whichever branch
// happens to fall through: the fact states what was checked and found, and
// never asserts a failure it did not observe.
func (e scanEntry) unresolved() string {
	switch {
	case !e.userKnown && !e.groupKnown:
		return "user and group"
	case !e.userKnown:
		return "user"
	case !e.groupKnown:
		return "group"
	default:
		return ""
	}
}

// formatMode renders mode the way ls does: a type character followed by nine
// permission characters, with the setuid, setgid and sticky bits shown in the
// execute position of their triad and capitalized when execute is not set.
// Go's own FileMode.String prefixes those bits instead, rendering a setuid
// binary as "urwxr-xr-x" where an operator reading a security report expects
// "-rwsr-xr-x".
func formatMode(mode fs.FileMode) string {
	out := []byte("----------")

	switch {
	case mode&fs.ModeDir != 0:
		out[0] = 'd'
	case mode&fs.ModeSymlink != 0:
		out[0] = 'l'
	}

	const permChars = "rwxrwxrwx"
	perm := mode.Perm()
	for i := range permChars {
		if perm&(1<<(len(permChars)-1-i)) != 0 {
			out[i+1] = permChars[i]
		}
	}

	special := []struct {
		pos   int
		bit   fs.FileMode
		withX byte
		noX   byte
	}{
		{3, fs.ModeSetuid, 's', 'S'},
		{6, fs.ModeSetgid, 's', 'S'},
		{9, fs.ModeSticky, 't', 'T'},
	}
	for _, sp := range special {
		if mode&sp.bit == 0 {
			continue
		}
		if out[sp.pos] == 'x' {
			out[sp.pos] = sp.withX
			continue
		}
		out[sp.pos] = sp.noX
	}

	return string(out)
}

// reportScan concludes the three traversal rules. A category with entries
// fails and carries them as evidence. One with none passes only when the
// traversal saw everything: after an incomplete scan, finding nothing is not
// the same as there being nothing to find.
func reportScan(r *report, scan fsScan, scanErr error) {
	var incomplete string
	switch {
	case scanErr != nil:
		incomplete = fmt.Sprintf("filesystem scan did not complete: %v", scanErr)
	case scan.unreadable > 0:
		incomplete = fmt.Sprintf("%d paths were unreadable and went unscanned; rerun with elevated privileges for complete coverage",
			scan.unreadable)
	}

	categories := []struct {
		entries []scanEntry
		key     registry.FindingKey
	}{
		{scan.suid, ruleSetID},
		{scan.worldWrite, ruleWorldWritable},
		{scan.unowned, ruleUnowned},
	}

	for _, category := range categories {
		switch {
		case len(category.entries) > 0:
			found := make([]types.Evidence, 0, len(category.entries))
			for _, entry := range category.entries {
				found = append(found, entry.evidence())
			}
			r.observed(category.key, found...)
		case incomplete != "":
			r.inconclusive(types.ResultError, incomplete, category.key)
		default:
			r.pass(category.key)
		}
	}

	if incomplete != "" {
		r.note(types.SymbolWarning, "%s", incomplete)
	}
}
