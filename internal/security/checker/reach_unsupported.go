//go:build darwin || openbsd || netbsd

// internal/security/checker/reach_unsupported.go

package checker

import (
	"context"
	"io/fs"
)

// deniedJudge decides what a directory confers when its mode bits deny
// traversal. What grants traversal beyond the mode bits on macOS, OpenBSD
// and NetBSD is not read yet and has not been verified on a real host, so no
// directory there is called root-only.
type deniedJudge struct{}

func (deniedJudge) reach(context.Context, string, fs.FileMode, uint32, uint32) reachability {
	return reachUnsupported
}
