// internal/sockets/sockets.go

// Package sockets reads the host's own sockets: every one the host reports, in
// every state. It reads the host's table of them and connects to nothing. It
// owns the serializable projection of what it read, so a live run and a saved
// report carry the same data.
package sockets

import (
	"cmp"
	"errors"
	"net"
	"strconv"
	"strings"
)

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

// States, in the words netstat prints for a TCP socket. They are declared
// once because every platform's reader and every rule that reads a state must
// agree on the spelling. A socket with no connection state of its own, as a
// bound UDP socket, is StateUnconnected, which is ss's word for it. A state a
// reader has no name for is reported as the number the host gave.
const (
	StateListen        = "LISTEN"
	StateEstablished   = "ESTABLISHED"
	StateSynSent       = "SYN_SENT"
	StateSynRecv       = "SYN_RECV"
	StateFinWait1      = "FIN_WAIT1"
	StateFinWait2      = "FIN_WAIT2"
	StateTimeWait      = "TIME_WAIT"
	StateClose         = "CLOSE"
	StateCloseWait     = "CLOSE_WAIT"
	StateLastAck       = "LAST_ACK"
	StateClosing       = "CLOSING"
	StateNewSynRecv    = "NEW_SYN_RECV"
	StateDeleteTCB     = "DELETE_TCB"
	StateUnconnected   = "UNCONN"
	StateConnecting    = "CONNECTING"
	StateDisconnecting = "DISCONNECTING"
)

// Gaps: why the processes holding a socket are missing or incomplete. A gap
// is stated rather than left blank, so a reader can tell a socket nobody owns
// from one whose owner the run could not see.
const (
	// GapNotPermitted means a process is known to hold the socket and this
	// run was refused when it tried to read that process.
	GapNotPermitted = "not permitted (try an elevated run: sudo, or an administrator terminal)"

	// GapUndetermined means this run could not tell whether a process holds
	// the socket, because it may not see every process. Only a privileged
	// run can conclude that nothing does.
	GapUndetermined = "owner not determined (try an elevated run: sudo, or an administrator terminal)"

	// GapUnreadable means the run already has the privilege an elevated run
	// would add and the host still does not let it read the process, as for
	// the Windows System process. Advising an elevated run there would
	// mislead.
	GapUnreadable = "not readable, even from an elevated run"

	// GapExited means the process ended between the host listing the socket
	// and this run reading the process.
	GapExited = "process ended before it could be read"

	// GapNoOwner means no process holds the socket, as for one in TIME_WAIT.
	GapNoOwner = "no owning process"
)

// ErrUnsupported is returned by Read on a platform whose sockets are not
// read, so the caller reports sockets as not evaluated there.
var ErrUnsupported = errors.New("sockets: not read on this platform")

type (
	// Socket is one socket as the host reports it. Local and Remote are an
	// address and port, or for a unix socket the path it is bound to. Remote
	// is empty for a socket with no peer. Type is the socket type of a unix
	// or packet socket (stream, dgram, seqpacket, raw). Scope applies to
	// internet sockets and is empty for the others.
	//
	// Owner is the account the host itself reports as the socket's owner.
	// Linux reports one for internet and packet sockets and none for unix
	// sockets, and Windows reports none; the account a holding process runs
	// as is Process.User. Processes are the processes that hold the socket
	// open, every one this run could read, in pid order. Where they are
	// missing or incomplete, Gap says why, and what was read is kept:
	// Windows reports the pid without privilege, so a Process can hold the
	// pid alone.
	Socket struct {
		Protocol  string    `json:"protocol" yaml:"protocol"`
		Type      string    `json:"type,omitempty" yaml:"type,omitempty"`
		State     string    `json:"state,omitempty" yaml:"state,omitempty"`
		Local     string    `json:"local" yaml:"local"`
		Remote    string    `json:"remote,omitempty" yaml:"remote,omitempty"`
		Scope     string    `json:"scope,omitempty" yaml:"scope,omitempty"`
		Owner     string    `json:"owner,omitempty" yaml:"owner,omitempty"`
		Processes []Process `json:"processes,omitempty" yaml:"processes,omitempty"`
		Gap       string    `json:"gap,omitempty" yaml:"gap,omitempty"`

		// Inode joins a socket to the processes holding it on Linux and is
		// kept in the report so the join can be checked.
		Inode string `json:"inode,omitempty" yaml:"inode,omitempty"`
	}

	// Process is a process that holds a socket. Path is the executable,
	// which is what a later association with an installed package and its
	// vulnerabilities joins on. User is the account the process runs as, which
	// is not necessarily the account that created the socket: a descriptor can
	// be inherited or passed to another process.
	Process struct {
		PID  int    `json:"pid" yaml:"pid"`
		Name string `json:"name,omitempty" yaml:"name,omitempty"`
		Path string `json:"path,omitempty" yaml:"path,omitempty"`
		User string `json:"user,omitempty" yaml:"user,omitempty"`
	}

	// View is the serializable projection of the host's sockets, grouped
	// by category. Unattributed counts the sockets whose processes this run
	// could not read, so a report states how much of it is unattributed. A
	// socket no process holds is not counted. A saved report records the
	// remote end of every connection and so discloses who the host was
	// talking to.
	View struct {
		Internet     []Socket `json:"internet,omitempty" yaml:"internet,omitempty"`
		Unix         []Socket `json:"unix,omitempty" yaml:"unix,omitempty"`
		Raw          []Socket `json:"raw,omitempty" yaml:"raw,omitempty"`
		Packet       []Socket `json:"packet,omitempty" yaml:"packet,omitempty"`
		Unattributed int      `json:"unattributed" yaml:"unattributed"`

		// NotRead names the categories this platform does not read, so an
		// absent category is not mistaken for a host with no such sockets.
		NotRead []string `json:"not_read,omitempty" yaml:"not_read,omitempty"`
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
// whose processes could not be read.
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

// compareSockets orders sockets by protocol, then local and remote end, then
// inode, so a report is the same from run to run whatever order the host
// listed them in.
func compareSockets(a, b Socket) int {
	return cmp.Or(
		strings.Compare(a.Protocol, b.Protocol),
		compareEnds(a.Local, b.Local),
		compareEnds(a.Remote, b.Remote),
		strings.Compare(a.Inode, b.Inode))
}

// compareEnds orders two ends by address and then by port as a number, so
// port 22 is listed before port 135 as netstat lists them. An end that is not
// an address and port, as a unix socket's path, is ordered as text.
func compareEnds(a, b string) int {
	aHost, aPort, aErr := net.SplitHostPort(a)
	bHost, bPort, bErr := net.SplitHostPort(b)
	if aErr != nil || bErr != nil {
		return strings.Compare(a, b)
	}
	aNumber, aErr := strconv.Atoi(aPort)
	bNumber, bErr := strconv.Atoi(bPort)
	if aErr != nil || bErr != nil {
		return strings.Compare(a, b)
	}
	return cmp.Or(strings.Compare(aHost, bHost), cmp.Compare(aNumber, bNumber))
}
