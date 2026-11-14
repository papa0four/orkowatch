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
	"strings"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
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

	// aclWalk carries the state one traversal accumulates. named holds the
	// paths, folded to lower case, whose inherited grants are reported too.
	aclWalk struct {
		reader     *aclReader
		report     *report
		root       string
		named      map[string]bool
		unreadable int
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

// scanACLs walks root once and concludes the access control rules. The root
// and the named system paths are judged on every grant they carry; every
// other entry only on grants set on it directly, because an inherited grant
// is the parent's finding and repeating it on each descendant is what buried
// the report in duplicates. A rule nothing failed passes only when the
// traversal read everything: after an incomplete one, finding nothing is not
// the same as there being nothing to find.
func (p *WindowsPermissionChecker) scanACLs(ctx context.Context, root string, r *report) {
	reader, err := newACLReader()
	if err != nil {
		r.inconclusive(finding.ResultError, fmt.Sprintf("access control lists could not be read: %v", err), aclRules...)
		return
	}

	w := &aclWalk{reader: reader, report: r, root: root, named: map[string]bool{strings.ToLower(root): true}}
	for _, path := range p.paths {
		w.named[strings.ToLower(path)] = true
	}

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return w.visit(path, d, walkErr)
	})

	var incomplete string
	switch {
	case err != nil:
		incomplete = fmt.Sprintf("traversal of %s did not complete: %v", root, err)
	case w.unreadable > 0:
		incomplete = fmt.Sprintf("%d paths under %s were unreadable and went unscanned; rerun with elevated privileges for complete coverage",
			w.unreadable, root)
	}
	if incomplete != "" {
		r.inconclusive(finding.ResultError, incomplete, aclRules...)
		r.note(finding.SymbolWarning, "%s", incomplete)
	}
	r.pass(aclRules...)
}

// visit handles one traversal entry. An entry that cannot be read is counted.
// A reparse point other than the root is not followed: junctions, symbolic
// links and volume mount points all lead off the tree being scanned, which
// keeps the walk on one volume the way the Unix scan stays on one filesystem.
func (w *aclWalk) visit(path string, d fs.DirEntry, walkErr error) error {
	if walkErr != nil {
		w.unreadable++
		if d != nil && d.IsDir() {
			return fs.SkipDir
		}
		return nil
	}

	if path != w.root && isReparsePoint(d) {
		if d.IsDir() {
			return fs.SkipDir
		}
		return nil
	}

	grants, open, err := w.reader.grants(path)
	switch {
	case err != nil:
		w.unreadable++
	case open:
		w.report.observed(ruleEveryoneFull, evidence(kindACL, path,
			"principal", "everyone", "access", accessFull, "scope", "no access control list"))
	default:
		w.judge(path, grants, w.named[strings.ToLower(path)])
	}
	return nil
}

// judge records the rules path's grants trip. inherited selects whether
// grants the entry inherited are judged along with the ones set on it.
func (w *aclWalk) judge(path string, grants []aclGrant, inherited bool) {
	for _, grant := range grants {
		if !inherited && grant.flags&aceInherited != 0 {
			continue
		}
		level := accessLevel(grant.mask)
		if level == "" {
			continue
		}

		group, broad := w.reader.broadGroup(grant.sid)
		if broad {
			who := w.reader.resolve(grant.sid)
			subject := evidence(kindACL, path,
				"principal", who.name, "sid", grant.sid.String(), "access", level, "scope", grantScope(grant.flags))
			switch {
			case level == accessFull && group == windows.WinWorldSid:
				w.report.observed(ruleEveryoneFull, subject)
			case level == accessFull && group == windows.WinBuiltinUsersSid:
				w.report.observed(ruleUsersFull, subject)
			default:
				w.report.observed(ruleBroadWrite, subject)
			}
			continue
		}

		// Only account SIDs can be orphaned; resolving them is the one
		// lookup the traversal makes, once per distinct SID.
		sid := grant.sid.String()
		if !strings.HasPrefix(sid, accountSIDPrefix) {
			continue
		}
		if who := w.reader.resolve(grant.sid); !who.resolved {
			w.report.observed(ruleUnresolvedSID, evidence(kindACL, path,
				"sid", sid, "access", level, "scope", grantScope(grant.flags)))
		}
	}
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
