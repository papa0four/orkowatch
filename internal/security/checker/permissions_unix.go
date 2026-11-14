//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/security/checker/permissions_unix.go

package checker

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/treewalk"
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
	// lookup per file to one per identifier. mu guards both maps, because the
	// scan's workers consult the cache at once.
	identityCache struct {
		mu     sync.RWMutex
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

	// fsWalk is what every worker of one filesystem traversal shares, all of
	// it either read-only or guarding itself. rootDev bounds the walk to the
	// filesystem the root lives on, and denied is the platform's judgment of
	// a directory whose mode bits deny traversal. What a worker finds is
	// returned from its visit rather than written here.
	fsWalk struct {
		ids     *identityCache
		rootDev uint64
		denied  *deniedJudge
	}

	// reachability is whether a principal other than root can traverse to an
	// entry. The zero value is reachNonRoot so an entry the walk failed to
	// judge is over-reported rather than quietly excused. Values are ordered
	// from widest to narrowest, so the narrower of two is the greater.
	reachability uint8

	// identityKind selects which account database a lookup consults.
	identityKind string
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

// The rules this check concludes: two judged on the critical paths, three on
// every entry the traversal visits.
const (
	ruleExcessMode    registry.FindingKey = "permissions.path_exceeds_expected_mode"
	ruleNotRootOwned  registry.FindingKey = "permissions.critical_path_not_root_owned"
	ruleSetID         registry.FindingKey = "permissions.suid_sgid_binary"
	ruleWorldWritable registry.FindingKey = "permissions.world_writable_file"
	ruleUnowned       registry.FindingKey = "permissions.unowned_file"
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
//
// Nearly every lookup is a hit and takes only the read lock. A miss takes the
// write lock for the whole name service query and checks again once it holds
// it, so two workers that miss on the same identifier produce one query, and
// the map is never written while another worker reads it.
func (c *identityCache) known(ctx context.Context, cache map[uint32]bool, kind identityKind, id uint32) bool {
	c.mu.RLock()
	resolved, seen := cache[id]
	c.mu.RUnlock()
	if seen {
		return resolved
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if resolved, seen := cache[id]; seen {
		return resolved
	}
	resolved = nameServiceKnows(ctx, kind, id)
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

// Check implements PermissionChecker interface for Unix systems
func (p *UnixPermissionChecker) Check(ctx context.Context) finding.AuditResult {
	r := newReport(p.checkIdentity)

	root, err := p.effectiveRoot()
	if err != nil {
		r.inconclusive(finding.ResultError, fmt.Sprintf("scan root could not be resolved: %v", err),
			ruleExcessMode, ruleNotRootOwned, ruleSetID, ruleWorldWritable, ruleUnowned)
		return r.finish()
	}

	r.note(finding.SymbolInfo, "Scanning %s", root)
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
		r.inconclusive(finding.ResultNotApplicable, "no critical system paths lie within "+root,
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
		r.note(finding.SymbolInfo, "Path does not exist: %s", cp.path)
		return
	case err != nil:
		r.inconclusive(finding.ResultError, fmt.Sprintf("%s could not be checked: %v", cp.path, err),
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
		r.inconclusive(finding.ResultError, cp.path+" ownership could not be determined", ruleNotRootOwned)
	case uid != rootUID:
		r.observed(ruleNotRootOwned, evidence(kindFile, cp.path,
			"description", cp.description,
			"uid", strconv.FormatUint(uint64(uid), decimalBase),
			"expected", "root"))
	case modeOK:
		r.note(finding.SymbolOK, "%s has correct permissions and ownership: %s root", cp.path, formatMode(mode))
	}
}

// scanFilesystem reads the tree under the effective root once, collecting
// setuid, group- and world-writable, and unowned entries together. Identity
// lookups are cached per identifier rather than performed per entry, which is
// what makes a single pass cheaper than the three it replaces. The walk stays
// on the root's filesystem: pseudo-filesystems and network mounts are out of
// scope and can be pathologically slow to traverse.
//
// Directories are read by scanWorkers workers at once. Each directory carries
// the reachability its parent conferred, each visit returns what it found,
// and the results are merged by one goroutine and sorted by path, so the
// report is the same from run to run whatever order the workers finished in.
func (p *UnixPermissionChecker) scanFilesystem(ctx context.Context, root string) (fsScan, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return fsScan{}, fmt.Errorf("stat scan root %s: %w", root, err)
	}
	uid, gid, rootDev, ok := fileIdentity(rootInfo)
	if !ok {
		return fsScan{}, fmt.Errorf("stat scan root %s: no filesystem identity", root)
	}

	w := &fsWalk{ids: newIdentityCache(), rootDev: rootDev, denied: &deniedJudge{}}

	// The root is an entry too. Nothing above it is examined, so it starts
	// reachable and confers on its contents whatever its own mode allows.
	var scan fsScan
	w.classify(ctx, &scan, root, rootInfo, uid, gid, reachNonRoot)
	if !rootInfo.IsDir() {
		return scan, nil
	}
	start := treewalk.Dir[reachability]{
		Path:  root,
		State: w.conferred(ctx, root, reachNonRoot, rootInfo.Mode(), uid, gid),
	}

	err = treewalk.Run(ctx, scanWorkers, start, w.readDir, scan.merge)
	scan.sort()
	return scan, err
}

// readDir handles one directory: an entry that cannot be read or identified
// is counted, an entry on another filesystem is skipped along with its
// subtree, and everything else is classified. It runs on several workers at
// once and keeps what it finds in its own result.
func (w *fsWalk) readDir(ctx context.Context, dir treewalk.Dir[reachability]) ([]treewalk.Dir[reachability], fsScan) {
	var found fsScan
	entries, err := os.ReadDir(dir.Path)
	if err != nil {
		found.unreadable++
		return nil, found
	}

	var subdirs []treewalk.Dir[reachability]
	for _, entry := range entries {
		if ctx.Err() != nil {
			break
		}

		info, err := entry.Info()
		if err != nil {
			found.unreadable++
			continue
		}
		uid, gid, dev, ok := fileIdentity(info)
		if !ok {
			found.unreadable++
			continue
		}
		if dev != w.rootDev {
			continue
		}

		path := filepath.Join(dir.Path, entry.Name())
		w.classify(ctx, &found, path, info, uid, gid, dir.State)
		if entry.IsDir() {
			subdirs = append(subdirs, treewalk.Dir[reachability]{
				Path:  path,
				State: w.conferred(ctx, path, dir.State, info.Mode(), uid, gid),
			})
		}
	}
	return subdirs, found
}

// classify records the entry in found under each category it belongs to.
// Setuid and world-writable apply to regular files only; ownership applies to
// every entry.
func (w *fsWalk) classify(ctx context.Context, found *fsScan, path string, info fs.FileInfo, uid, gid uint32, reach reachability) {
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
			found.suid = append(found.suid, entry)
		}
		if mode.Perm()&bitWorldWritable != 0 {
			found.worldWrite = append(found.worldWrite, entry)
		}
	}

	if !userKnown || !groupKnown {
		found.unowned = append(found.unowned, entry)
	}
}

// conferred returns what dir confers on its contents, given what its own
// parent conferred on it. An entry is only as reachable as the directories
// that must be traversed to arrive at it, whatever its own mode says, so a
// directory only root can traverse makes everything beneath it root-only and
// reachability only ever narrows on the way down. The platform is asked only
// about a directory mode bits deny and whose chain is not already root-only,
// which keeps that cost off every other directory.
func (w *fsWalk) conferred(ctx context.Context, dir string, parent reachability, mode fs.FileMode, uid, gid uint32) reachability {
	if parent != reachRootOnly && !traversableByNonRoot(mode, uid, gid) {
		return max(parent, w.denied.reach(ctx, dir, mode))
	}
	return parent
}

// merge folds one visit's findings into s. The traversal calls it from one
// goroutine at a time.
func (s *fsScan) merge(found fsScan) {
	s.suid = append(s.suid, found.suid...)
	s.worldWrite = append(s.worldWrite, found.worldWrite...)
	s.unowned = append(s.unowned, found.unowned...)
	s.unreadable += found.unreadable
}

// sort orders every category by path, which is what makes the report
// independent of the order the workers finished in.
func (s *fsScan) sort() {
	byPath := func(a, b scanEntry) int { return strings.Compare(a.path, b.path) }
	slices.SortFunc(s.suid, byPath)
	slices.SortFunc(s.worldWrite, byPath)
	slices.SortFunc(s.unowned, byPath)
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
func (e scanEntry) evidence() finding.Evidence {
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
			found := make([]finding.Evidence, 0, len(category.entries))
			for _, entry := range category.entries {
				found = append(found, entry.evidence())
			}
			r.observed(category.key, found...)
		case incomplete != "":
			r.inconclusive(finding.ResultError, incomplete, category.key)
		default:
			r.pass(category.key)
		}
	}

	if incomplete != "" {
		r.note(finding.SymbolWarning, "%s", incomplete)
	}
}
