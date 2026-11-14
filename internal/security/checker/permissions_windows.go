//go:build windows

// internal/security/checker/permissions_windows.go

package checker

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/treewalk"
)

// The rules this check concludes: four judged on access control entries, one
// on the share listing.
const (
	ruleEveryoneFull  registry.FindingKey = "permissions.everyone_full_control"
	ruleUsersFull     registry.FindingKey = "permissions.users_full_control"
	ruleBroadWrite    registry.FindingKey = "permissions.broad_group_write_access"
	ruleUnresolvedSID registry.FindingKey = "permissions.unresolved_sid_grant"
	ruleAdminShare    registry.FindingKey = "permissions.admin_share_present"
)

type (
	// WindowsPermissionChecker implements PermissionChecker for Windows
	// systems. paths are the system locations judged in full wherever they
	// fall inside the traversal.
	WindowsPermissionChecker struct {
		checkIdentity
		paths    []string
		scanRoot string
	}

	// aclWalk is what every worker of one traversal shares. readers holds one
	// access list reader per worker: a visit takes one for its duration and
	// puts it back, so no reader, and no buffer or name cache inside one, is
	// ever used by two workers at once. named holds the paths, folded to
	// lower case, whose inherited grants are reported too; it is only read.
	aclWalk struct {
		readers chan *aclReader
		named   map[string]bool
	}

	// aclFound is what one visit found, returned to the traversal rather
	// than written anywhere shared.
	aclFound struct {
		grants     []ruleGrant
		unreadable int
	}

	// ruleGrant is one grant and the rule it trips.
	ruleGrant struct {
		key     registry.FindingKey
		subject finding.Evidence
	}
)

// aclRules are the rules the traversal concludes.
var aclRules = []registry.FindingKey{ruleEveryoneFull, ruleUsersFull, ruleBroadWrite, ruleUnresolvedSID}

// NewPermissionChecker returns the file permission checker for Windows
// hosts. scanRoot narrows the traversal to one tree; empty means the whole
// system volume.
func NewPermissionChecker(osCtx registry.OSContext, scanRoot string) *WindowsPermissionChecker {
	return &WindowsPermissionChecker{
		checkIdentity: checkIdentity{
			domain:   "File Permissions Security",
			analyzes: "file and directory permissions",
			osCtx:    osCtx,
		},
		paths: []string{
			"C:\\Windows\\System32",
			"C:\\Program Files",
			"C:\\Program Files (x86)",
			"C:\\ProgramData",
			"C:\\Users",
		},
		scanRoot: scanRoot,
	}
}

// Check implements PermissionChecker interface for Windows systems
func (p *WindowsPermissionChecker) Check(ctx context.Context) finding.AuditResult {
	r := newReport(p.checkIdentity)

	root := p.effectiveRoot()
	r.note(finding.SymbolInfo, "Scanning %s", root)
	p.scanACLs(ctx, root, r)

	// Shares are a host-wide condition rather than a property of the scanned
	// tree, so they are enumerated whether or not a path narrowed the run.
	p.checkNetworkShares(ctx, r)

	return r.finish()
}

// effectiveRoot returns the operator's scan root when one was supplied and
// the root of the system volume otherwise, which is the Windows counterpart
// of scanning from / on Unix.
func (p *WindowsPermissionChecker) effectiveRoot() string {
	if p.scanRoot != "" {
		return filepath.Clean(p.scanRoot)
	}
	if volume := filepath.VolumeName(os.Getenv("SystemRoot")); volume != "" {
		return volume + `\`
	}
	return `C:\`
}

// scanACLs reads the tree under root once and concludes the access control
// rules. The root and the named system paths are judged on every grant they
// carry; every other entry only on grants set on it directly, because an
// inherited grant is the parent's finding and repeating it on each descendant
// is what buried the report in duplicates. A rule nothing failed passes only
// when the traversal read everything: after an incomplete one, finding
// nothing is not the same as there being nothing to find.
//
// Directories are read by scanWorkers workers at once. Each visit returns
// what it found, the results are merged by one goroutine and sorted by path,
// and only then recorded, so the report is touched by this goroutine alone
// and reads the same from run to run.
func (p *WindowsPermissionChecker) scanACLs(ctx context.Context, root string, r *report) {
	w := &aclWalk{
		readers: make(chan *aclReader, scanWorkers),
		named:   map[string]bool{strings.ToLower(root): true},
	}
	for range scanWorkers {
		reader, err := newACLReader()
		if err != nil {
			r.inconclusive(finding.ResultError, fmt.Sprintf("access control lists could not be read: %v", err), aclRules...)
			return
		}
		w.readers <- reader
	}
	for _, path := range p.paths {
		w.named[strings.ToLower(path)] = true
	}

	// The root is an entry too, and the walk only visits what lies under it.
	var total aclFound
	reader := <-w.readers
	w.inspect(reader, root, &total)
	w.readers <- reader

	err := treewalk.Run(ctx, scanWorkers, treewalk.Dir[struct{}]{Path: root}, w.readDir, total.merge)

	slices.SortStableFunc(total.grants, func(a, b ruleGrant) int {
		if byPath := strings.Compare(a.subject.Subject, b.subject.Subject); byPath != 0 {
			return byPath
		}
		return strings.Compare(string(a.key), string(b.key))
	})
	for _, grant := range total.grants {
		r.observed(grant.key, grant.subject)
	}

	var incomplete string
	switch {
	case err != nil:
		incomplete = fmt.Sprintf("traversal of %s did not complete: %v", root, err)
	case total.unreadable > 0:
		incomplete = fmt.Sprintf("%d paths under %s were unreadable and went unscanned; rerun with elevated privileges for complete coverage",
			total.unreadable, root)
	}
	if incomplete != "" {
		r.inconclusive(finding.ResultError, incomplete, aclRules...)
		r.note(finding.SymbolWarning, "%s", incomplete)
	}
	r.pass(aclRules...)
}

// readDir handles one directory. A directory that cannot be listed is
// counted. A reparse point is not inspected or followed: junctions, symbolic
// links and volume mount points all lead off the tree being scanned, which
// keeps the walk on one volume the way the Unix scan stays on one filesystem.
// It runs on several workers at once and keeps what it finds in its own
// result.
func (w *aclWalk) readDir(ctx context.Context, dir treewalk.Dir[struct{}]) ([]treewalk.Dir[struct{}], aclFound) {
	reader := <-w.readers
	defer func() { w.readers <- reader }()

	var found aclFound
	entries, err := os.ReadDir(dir.Path)
	if err != nil {
		found.unreadable++
		return nil, found
	}

	var subdirs []treewalk.Dir[struct{}]
	for _, entry := range entries {
		if ctx.Err() != nil {
			break
		}
		if isReparsePoint(entry) {
			continue
		}

		path := filepath.Join(dir.Path, entry.Name())
		w.inspect(reader, path, &found)
		if entry.IsDir() {
			subdirs = append(subdirs, treewalk.Dir[struct{}]{Path: path})
		}
	}
	return subdirs, found
}

// inspect reads one entry's access control list and records in found what
// its grants trip. An entry whose list cannot be read is counted.
func (w *aclWalk) inspect(reader *aclReader, path string, found *aclFound) {
	grants, open, err := reader.grants(path)
	switch {
	case err != nil:
		found.unreadable++
	case open:
		found.add(ruleEveryoneFull, evidence(kindACL, path,
			"principal", "everyone", "access", accessFull, "scope", "no access control list"))
	default:
		judgeGrants(reader, path, grants, w.named[strings.ToLower(path)], found)
	}
}

// judgeGrants records the rules path's grants trip. inherited selects whether
// grants the entry inherited are judged along with the ones set on it.
func judgeGrants(reader *aclReader, path string, grants []aclGrant, inherited bool, found *aclFound) {
	for _, grant := range grants {
		if !inherited && grant.flags&aceInherited != 0 {
			continue
		}
		level := accessLevel(grant.mask)
		if level == "" {
			continue
		}

		group, broad := reader.broadGroup(grant.sid)
		if broad {
			who := reader.resolve(grant.sid)
			subject := evidence(kindACL, path,
				"principal", who.name, "sid", grant.sid.String(), "access", level, "scope", grantScope(grant.flags))
			switch {
			case level == accessFull && group == windows.WinWorldSid:
				found.add(ruleEveryoneFull, subject)
			case level == accessFull && group == windows.WinBuiltinUsersSid:
				found.add(ruleUsersFull, subject)
			default:
				found.add(ruleBroadWrite, subject)
			}
			continue
		}

		// Only account SIDs can be orphaned; resolving them is the one
		// lookup the traversal makes, once per distinct SID per reader.
		sid := grant.sid.String()
		if !strings.HasPrefix(sid, accountSIDPrefix) {
			continue
		}
		if who := reader.resolve(grant.sid); !who.resolved {
			found.add(ruleUnresolvedSID, evidence(kindACL, path,
				"sid", sid, "access", level, "scope", grantScope(grant.flags)))
		}
	}
}

// add records one grant against the rule it trips.
func (f *aclFound) add(key registry.FindingKey, subject finding.Evidence) {
	f.grants = append(f.grants, ruleGrant{key: key, subject: subject})
}

// merge folds one visit's findings into f. The traversal calls it from one
// goroutine at a time.
func (f *aclFound) merge(found aclFound) {
	f.grants = append(f.grants, found.grants...)
	f.unreadable += found.unreadable
}

// isReparsePoint reports whether a directory entry is a reparse point, read
// from the attributes the directory listing already returned.
func isReparsePoint(d fs.DirEntry) bool {
	info, err := d.Info()
	if err != nil {
		return false
	}
	attrs, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && attrs.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

// checkNetworkShares concludes the administrative share rule and narrates
// the other shares the host exports.
func (p *WindowsPermissionChecker) checkNetworkShares(ctx context.Context, r *report) {
	output, err := exec.CommandContext(ctx, "net", "share").Output()
	if err != nil {
		r.inconclusive(finding.ResultError,
			fmt.Sprintf("network shares could not be listed: %v", execError(err)), ruleAdminShare)
		return
	}

	r.section("Network Shares:")
	for _, share := range strings.Split(string(output), "\n") {
		share = strings.TrimSpace(share)
		if share == "" || strings.HasPrefix(share, "Share name") ||
			strings.HasPrefix(share, "---") {
			continue
		}

		switch name := strings.Fields(share)[0]; name {
		case "ADMIN$", "C$", "IPC$":
			r.observed(ruleAdminShare, evidence(kindShare, name, "listing", share))
		default:
			r.note(finding.SymbolInfo, "%s", share)
		}
	}
	r.pass(ruleAdminShare)
}
