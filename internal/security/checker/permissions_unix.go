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
	permStandardFile   os.FileMode = 0644
	permOwnerReadOnly  os.FileMode = 0400
	permSudoers        os.FileMode = 0440
	permOwnerReadWrite os.FileMode = 0600
	permStandardDir    os.FileMode = 0755
	permPrivateDir     os.FileMode = 0700
	permReadOnlyDir    os.FileMode = 0555

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

	// criticalPath represents a path that needs permission checking
	criticalPath struct {
		path        string
		description string
		expected    os.FileMode
		recursive   bool
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

	if p.scanRoot == "" {
		for _, cpath := range p.paths {
			if err := p.checkPathPermissions(ctx, cpath, &result); err != nil {
				result.Details = append(result.Details,
					fmt.Sprintf("%s Error checking %s: %v",
						types.SymbolError, cpath.path, err))
			}
		}
	}

	scan, err := p.scanFilesystem(ctx)
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

// effectiveRoot resolves the find scan root; operator supplied
func (p *UnixPermissionChecker) effectiveRoot() string {
	if p.scanRoot == "" {
		return "/"
	}
	return p.scanRoot
}

// commonCriticalPaths lists the paths every Unix-like platform is expected
// to protect; platformCriticalPaths adds the platform's own.
func commonCriticalPaths() []criticalPath {
	return []criticalPath{
		{"/etc/passwd", "Password file", permStandardFile, false},
		{"/etc/shadow", "Shadow password file", permOwnerReadOnly, false},
		{"/etc/group", "Group file", permStandardFile, false},
		{"/etc/sudoers", "Sudo configuration", permSudoers, false},
		{"/etc/ssh/sshd_config", "SSH daemon configuration", permOwnerReadWrite, false},
		{"/var/log", "Log directory", permStandardDir, true},
		{"/home", "User home directories", permStandardDir, true},
	}
}

func (p *UnixPermissionChecker) checkPathPermissions(ctx context.Context, cp criticalPath, result *types.AuditResult) error {
	info, err := os.Stat(cp.path)
	if err != nil {
		if os.IsNotExist(err) {
			result.Details = append(result.Details,
				fmt.Sprintf("%s Path does not exist: %s", types.SymbolInfo, cp.path))
			return nil
		}
		return err
	}

	mode := info.Mode()
	if mode.Perm() > cp.expected {
		result.Details = append(result.Details,
			fmt.Sprintf("%s WARNING: %s (%s) has permissions %v, expected %v",
				types.SymbolWarning, cp.path, cp.description, mode.Perm(), cp.expected))
		emitFinding(result, p.osCtx, "permissions.path_exceeds_expected_mode")
	} else {
		result.Details = append(result.Details,
			fmt.Sprintf("%s %s has correct permissions: %v",
				types.SymbolOK, cp.path, mode.Perm()))
	}

	if cp.recursive && info.IsDir() {
		return filepath.Walk(cp.path, func(path string, info os.FileInfo, err error) error {
			// Abort the walk as soon as the caller's deadline expires;
			// returning the ctx error stops filepath.Walk immediately.
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if err != nil {
				return nil // Skip files we can't access
			}

			mode := info.Mode()
			if mode&bitWorldWritable != 0 { // World-writable
				result.Details = append(result.Details,
					fmt.Sprintf("%s WARNING: %s is world-writable: %v",
						types.SymbolWarning, path, mode.Perm()))
			}
			return nil
		})
	}

	return nil
}

// scanFilesystem walks the effective root once, collecting setuid, group- and
// world-writable, and unowned entries together. Identity lookups are cached
// per identifier rather than performed per entry, which is what makes a single
// pass cheaper than the three it replaces. The walk stays on the root's
// filesystem: pseudo-filesystems and network mounts are out of scope and can
// be pathologically slow to traverse.
func (p *UnixPermissionChecker) scanFilesystem(ctx context.Context) (fsScan, error) {
	root := p.effectiveRoot()

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
	return fmt.Sprintf("%v uid=%d gid=%d %s", info.Mode(), uid, gid, path)
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
