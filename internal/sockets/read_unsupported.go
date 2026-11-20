//go:build !linux && !windows

// internal/sockets/read_unsupported.go

package sockets

import "context"

// Read reports ErrUnsupported: this platform's sockets are not read.
func Read(context.Context) (View, error) {
	return View{}, ErrUnsupported
}
