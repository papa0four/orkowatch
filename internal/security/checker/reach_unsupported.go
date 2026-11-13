//go:build darwin || freebsd || openbsd || netbsd

// internal/security/checker/reach_unsupported.go

package checker

import (
	"context"
	"io/fs"
)

// deniedJudge decides what a directory confers when its mode bits deny
// traversal. macOS and the BSDs carry access control lists this checker does
// not read yet, and their semantics have not been verified on a real host, so
// no directory there is called root-only.
type deniedJudge struct{}

func (deniedJudge) reach(context.Context, string, fs.FileMode) reachability {
	return reachUnsupported
}
