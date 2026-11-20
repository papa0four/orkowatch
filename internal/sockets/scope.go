//go:build linux || windows

// internal/sockets/scope.go

package sockets

import "net"

// scopeOf says which of the host's addresses a socket bound to ip answers on.
// It is built where a reader reads internet sockets.
func scopeOf(ip net.IP) string {
	switch {
	case ip.IsUnspecified():
		return ScopeWildcard
	case ip.IsLoopback():
		return ScopeLoopback
	default:
		return ScopeSpecific
	}
}
