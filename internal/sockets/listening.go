// internal/sockets/listening.go

package sockets

import "net"

// Listening reports whether s accepts traffic from a peer it has not heard
// from: a TCP socket in LISTEN, or a UDP socket bound with no peer.
func (s Socket) Listening() bool {
	switch s.Protocol {
	case TCP, TCP6:
		return s.State == StateListen
	case UDP, UDP6:
		return s.State == StateUnconnected
	default:
		return false
	}
}

// Port returns the local port of an internet socket, and false for any other.
func (s Socket) Port() (string, bool) {
	if s.Category() != CategoryInternet {
		return "", false
	}
	_, port, err := net.SplitHostPort(s.Local)
	return port, err == nil
}

// Listeners returns the internet sockets in v that are listening and that keep
// selects, in v's order. A nil keep selects every one.
func (v View) Listeners(keep func(Socket) bool) []Socket {
	var out []Socket
	for _, s := range v.Internet {
		if s.Listening() && (keep == nil || keep(s)) {
			out = append(out, s)
		}
	}
	return out
}
