//go:build linux || darwin || freebsd || openbsd || netbsd

// internal/security/checker/permissions_unix.go

package checker

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/security/types"
)

// Expected file and directory permission modes
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
		suid       []string
		worldWrite []string
		unowned    []string
		unreadable int
	}

	// fsWalk carries the state one filesystem traversal accumulates. rootDev
	// bounds the walk to the filesystem the root lives on.
	fsWalk struct {
		ids     *identityCache
		rootDev uint64
		scan    fsScan
	}

	// identityKind selects which account database a lookup consults.
	identityKind string
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

// resolves reports whether both identifiers map to a known principal.
func (c *identityCache) resolves(ctx context.Context, uid, gid uint32) bool {
	return c.known(ctx, c.users, identityKindUser, uid) &&
		c.known(ctx, c.groups, identityKindGroup, gid)
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

// Check implements PermissionChecker interface for Unix systems
func (p *UnixPermissionChecker) Check(ctx context.Context) types.AuditResult {
	result := types.AuditResult{
		Name:        p.Name(),
		Status:      types.StatusChecking,
		Description: p.Description(),
		Details:     make([]string, 0),
	}

	root, rootErr := p.effectiveRoot()
	if rootErr != nil {
		result.Status = types.StatusError
		result.Description = fmt.Sprintf("Scan root could not be resolved: %v", rootErr)
		result.Details = append(result.Details,
			fmt.Sprintf("%s Scan root could not be resolved: %v", types.SymbolError, rootErr))
		return result
	}

	result.Details = append(result.Details,
		fmt.Sprintf("%s Scanning %s", types.SymbolInfo, root))
	p.checkCriticalPaths(root, &result)

	scan, err := p.scanFilesystem(ctx, root)
	p.reportScan(&result, scan)

	switch {
	case err != nil:
		result.Status = types.StatusWarning
		result.Description = fmt.Sprintf("Filesystem scan did not complete: %v", err)
		result.Details = append(result.Details,
			fmt.Sprintf("%s Filesystem scan did not complete: %v", types.SymbolError, err))
	case scan.unreadable > 0:
		result.Status = types.StatusWarning
		result.Description = fmt.Sprintf("Filesystem scan could not read %d paths", scan.unreadable)
		result.Details = append(result.Details,
			fmt.Sprintf("%s %d paths were unreadable and went unscanned; rerun with elevated privileges for complete coverage",
				types.SymbolWarning, scan.unreadable))
	default:
		result.Status = types.StatusCompleted
	}
	return result
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
// invoked.
func (p *UnixPermissionChecker) checkCriticalPaths(root string, result *types.AuditResult) {
	seen := make(map[registry.FindingKey]struct{})
	var checked int

	for _, cpath := range p.paths {
		if !pathWithin(cpath.path, root) {
			continue
		}
		checked++
		if err := p.checkPathPermissions(cpath, result, seen); err != nil {
			result.Details = append(result.Details,
				fmt.Sprintf("%s Error checking %s: %v",
					types.SymbolError, cpath.path, err))
		}
	}

	if checked == 0 {
		result.Details = append(result.Details,
			fmt.Sprintf("%s No critical system paths lie within %s",
				types.SymbolInfo, root))
	}
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

// checkPathPermissions reports every way cp departs from what a critical
// system path must be. Both conditions are evaluated: a path can be both too
// permissive and wrongly owned, and reporting only the first would hide the
// second. Each finding is emitted at most once per run through seen, because
// the definitions describe the condition rather than the path.
func (p *UnixPermissionChecker) checkPathPermissions(cp criticalPath, result *types.AuditResult, seen map[registry.FindingKey]struct{}) error {
	info, err := os.Stat(cp.path)
	if err != nil {
		if os.IsNotExist(err) {
			result.Details = append(result.Details,
				fmt.Sprintf("%s Path does not exist: %s", types.SymbolInfo, cp.path))
			return nil
		}
		return err
	}

	problems := p.reportPathMode(cp, info, result, seen) + p.reportPathOwner(cp, info, result, seen)
	if problems == 0 {
		result.Details = append(result.Details,
			fmt.Sprintf("%s %s has correct permissions and ownership: %s root",
				types.SymbolOK, cp.path, formatMode(info.Mode())))
	}
	return nil
}

// reportPathMode reports a mode that grants access the expectation withholds,
// returning how many problems it found. The test is a bitmask rather than a
// numeric comparison: a mode is too permissive when it sets any bit the
// expectation does not, which a greater-than test misses whenever the extra
// access is numerically smaller, as 0044 is against an expected 0600. A
// stricter mode is never a finding.
func (p *UnixPermissionChecker) reportPathMode(cp criticalPath, info os.FileInfo, result *types.AuditResult, seen map[registry.FindingKey]struct{}) int {
	mode := info.Mode()
	if mode.Perm()&^cp.expected == 0 {
		return 0
	}

	result.Details = append(result.Details,
		fmt.Sprintf("%s WARNING: %s (%s) has permissions %s, expected no more than %s",
			types.SymbolWarning, cp.path, cp.description, formatMode(mode), formatMode(cp.expected)))
	emitFindingOnce(result, p.osCtx, "permissions.path_exceeds_expected_mode", seen)
	return 1
}

// reportPathOwner reports a critical path not owned by root, returning how
// many problems it found. Ownership is what makes a permissive-looking mode
// safe or unsafe: /etc/shadow at 0640 is the Debian design when root owns it
// and an exposure when an unprivileged account does.
func (p *UnixPermissionChecker) reportPathOwner(cp criticalPath, info os.FileInfo, result *types.AuditResult, seen map[registry.FindingKey]struct{}) int {
	uid, _, _, ok := fileIdentity(info)
	switch {
	case !ok:
		result.Details = append(result.Details,
			fmt.Sprintf("%s %s ownership could not be determined", types.SymbolWarning, cp.path))
		return 1
	case uid != rootUID:
		result.Details = append(result.Details,
			fmt.Sprintf("%s WARNING: %s (%s) is owned by uid %d, expected root",
				types.SymbolWarning, cp.path, cp.description, uid))
		emitFindingOnce(result, p.osCtx, "permissions.critical_path_not_root_owned", seen)
		return 1
	default:
		return 0
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

	w.classify(ctx, path, info, uid, gid)
	return nil
}

// classify records the entry under each category it belongs to. Setuid and
// world-writable apply to regular files only; ownership applies to every
// entry.
func (w *fsWalk) classify(ctx context.Context, path string, info fs.FileInfo, uid, gid uint32) {
	mode := info.Mode()
	if mode.IsRegular() {
		if mode&(os.ModeSetuid|os.ModeSetgid) != 0 {
			w.scan.suid = append(w.scan.suid, describeEntry(path, info, uid, gid))
		}
		if mode.Perm()&bitWorldWritable != 0 {
			w.scan.worldWrite = append(w.scan.worldWrite, describeEntry(path, info, uid, gid))
		}
	}

	if !w.ids.resolves(ctx, uid, gid) {
		w.scan.unowned = append(w.scan.unowned, describeEntry(path, info, uid, gid))
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

// describeEntry renders one entry with its mode and numeric owner and group.
// The identifiers stay numeric deliberately: for an unowned entry they are the
// values that failed to resolve, and a name would be misleading.
func describeEntry(path string, info fs.FileInfo, uid, gid uint32) string {
	return fmt.Sprintf("%s uid=%d gid=%d %s", formatMode(info.Mode()), uid, gid, path)
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

// reportScan records each category the traversal found.
func (p *UnixPermissionChecker) reportScan(result *types.AuditResult, scan fsScan) {
	sections := []struct {
		heading string
		entries []string
		key     registry.FindingKey
	}{
		{"SUID/SGID Files Found:", scan.suid, "permissions.suid_sgid_binary"},
		{"World-Writable Files Found:", scan.worldWrite, "permissions.world_writable_file"},
		{"Unowned Files Found:", scan.unowned, "permissions.unowned_file"},
	}

	for _, section := range sections {
		if len(section.entries) == 0 {
			continue
		}
		result.Details = append(result.Details, "", section.heading)
		for _, entry := range section.entries {
			result.Details = append(result.Details,
				fmt.Sprintf("%s %s", types.SymbolWarning, entry))
		}
		emitFinding(result, p.osCtx, section.key)
	}
}
