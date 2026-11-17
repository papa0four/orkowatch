// internal/sockets/sockets.go

// Package sockets reads the host's own sockets: every one the host reports, in
// every state. It reads the host's table of them and connects to nothing.
// It owns the serializable projection and its text rendering, so structured
// and text output cannot drift apart, and the audit consumes the same
// projection a saved report carries.
package sockets

import "errors"

// Protocols, named as the protocol column of netstat and ss names them.
const (
	TCP    = "tcp"
	TCP6   = "tcp6"
	UDP    = "udp"
	UDP6   = "udp6"
	Raw    = "raw"
	Raw6   = "raw6"
	Unix   = "unix"
	Packet = "packet"
)

// Categories group sockets under the headings of the host's own tools.
const (
	CategoryInternet = "internet"
	CategoryUnix     = "unix"
	CategoryRaw      = "raw"
	CategoryPacket   = "packet"
)

// Binding scopes: which of the host's addresses a socket answers on.
const (
	ScopeWildcard = "wildcard"
	ScopeLoopback = "loopback"
	ScopeSpecific = "specific"
)

// Gaps: why a socket's owner or process is incomplete. A gap is stated rather
// than left blank, so a reader can tell a socket nobody owns from one the run
// could not see the owner of.
const (
	// GapNotPermitted means the owner or its process exists and this run may
	// not read it.
	GapNotPermitted = "not permitted (try an elevated run: sudo, or an administrator terminal)"

	// GapUnreadable means the run already has the privilege an elevated run
	// would add and the host still does not let it read the owner, as for
	// the Windows System process. Advising an elevated run there would
	// mislead.
	GapUnreadable = "not readable, even from an elevated run"

	// GapNoOwner means the host reports no owning process, as for a socket
	// in TIME_WAIT.
	GapNoOwner = "no owning process"

	// GapNotRead means the platform does not report an owner for this
	// kind of socket.
	GapNotRead = "not read on this platform"
)

// ErrUnsupported is returned by Read on a platform whose sockets are not
// read, so the caller reports sockets as not evaluated there.
var ErrUnsupported = errors.New("sockets: not read on this platform")

type (
	// Socket is one socket as the host reports it. Local and Remote are an
	// address and port, or for a unix socket the path it is bound to. Remote
	// is empty for a socket with no peer. Type is the socket type of a unix
	// or packet socket (stream, dgram, seqpacket, raw). Scope applies to internet sockets
	// and is empty for the others. Owner is the account that owns the socket,
	// and Process the process that does. Where either could not be read in
	// full, Gap says why, and what was read is kept: Windows reports the pid
	// without privilege, so a Process can hold the pid alone.
	Socket struct {
		Protocol string   `json:"protocol" yaml:"protocol"`
		Type     string   `json:"type,omitempty" yaml:"type,omitempty"`
		State    string   `json:"state,omitempty" yaml:"state,omitempty"`
		Local    string   `json:"local" yaml:"local"`
		Remote   string   `json:"remote,omitempty" yaml:"remote,omitempty"`
		Scope    string   `json:"scope,omitempty" yaml:"scope,omitempty"`
		Owner    string   `json:"owner,omitempty" yaml:"owner,omitempty"`
		Process  *Process `json:"process,omitempty" yaml:"process,omitempty"`
		Gap      string   `json:"gap,omitempty" yaml:"gap,omitempty"`

		// Inode joins a socket to its owning process on Linux and is kept in
		// the report so the join can be checked.
		Inode string `json:"inode,omitempty" yaml:"inode,omitempty"`
	}

	// Process is the process that owns a socket. Path is the executable,
	// which is what a later association with an installed package and its
	// vulnerabilities joins on.
	Process struct {
		PID  int    `json:"pid" yaml:"pid"`
		Name string `json:"name" yaml:"name"`
		Path string `json:"path,omitempty" yaml:"path,omitempty"`
	}

	// View is the serializable projection of the host's sockets, grouped
	// by category. Unattributed counts the sockets whose owner this run
	// could not read, so a report states how much of it is unattributed and
	// why. A socket the host reports no owner for is not counted. A saved
	// report records the remote end of every connection and so discloses who
	// the host was talking to.
	View struct {
		Internet     []Socket `json:"internet" yaml:"internet"`
		Unix         []Socket `json:"unix" yaml:"unix"`
		Raw          []Socket `json:"raw" yaml:"raw"`
		Packet       []Socket `json:"packet" yaml:"packet"`
		Unattributed int      `json:"unattributed" yaml:"unattributed"`
	}
)

// Category returns the category s is listed under.
func (s Socket) Category() string {
	switch s.Protocol {
	case Unix:
		return CategoryUnix
	case Raw, Raw6:
		return CategoryRaw
	case Packet:
		return CategoryPacket
	default:
		return CategoryInternet
	}
}

// NewView groups sockets by category in the order given and counts those
// whose owner could not be read.
func NewView(sockets []Socket) View {
	var v View
	for _, s := range sockets {
		switch s.Category() {
		case CategoryUnix:
			v.Unix = append(v.Unix, s)
		case CategoryRaw:
			v.Raw = append(v.Raw, s)
		case CategoryPacket:
			v.Packet = append(v.Packet, s)
		default:
			v.Internet = append(v.Internet, s)
		}
		if s.Gap != "" && s.Gap != GapNoOwner {
			v.Unattributed++
		}
	}
	return v
}
