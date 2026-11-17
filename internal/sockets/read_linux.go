//go:build linux

// internal/sockets/read_linux.go

package sockets

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const (
	procRoot = "/proc"

	// The fields of a line of /proc/net/{tcp,udp,raw} and their v6 forms that
	// this reader uses. The columns before the inode are the same in all of
	// them.
	inetLocalField  = 1
	inetRemoteField = 2
	inetStateField  = 3
	inetUIDField    = 7
	inetInodeField  = 9
	inetFields      = inetInodeField + 1

	// A hex address is one 32-bit word per four bytes, each in the byte order
	// of the host that printed it.
	ipv4Hex   = 8
	ipv6Hex   = 32
	wordHex   = 8
	wordBytes = 4

	// The fields of a line of /proc/net/unix and /proc/net/packet.
	unixFlagsField = 3
	unixTypeField  = 4
	unixStateField = 5
	unixInodeField = 6
	unixPathField  = 7
	unixFields     = unixInodeField + 1

	packetTypeField  = 2
	packetIfaceField = 4
	packetUIDField   = 7
	packetInodeField = 8
	packetFields     = packetInodeField + 1

	// soAcceptConn is the flag the kernel sets on a unix socket that has
	// called listen, __SO_ACCEPTCON in include/uapi/linux/net.h.
	soAcceptConn = 1 << 16

	hexBase  = 16
	uidBits  = 32
	portBits = 16

	socketLinkPrefix = "socket:["
	noInode          = "0"
)

// tcpStates names the kernel's TCP states by their number, from the enum in
// include/net/tcp_states.h, in the vocabulary netstat prints.
var tcpStates = map[uint64]string{
	1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1", 5: "FIN_WAIT2",
	6: "TIME_WAIT", 7: "UNCONN", 8: "CLOSE_WAIT", 9: "LAST_ACK", 10: "LISTEN",
	11: "CLOSING", 12: "NEW_SYN_RECV",
}

// unixStates names the state of a unix socket that is not listening, by the
// socket_state value /proc/net/unix prints, from include/uapi/linux/net.h.
var unixStates = map[uint64]string{
	1: "UNCONN", 2: "CONNECTING", 3: "ESTABLISHED", 4: "DISCONNECTING",
}

// unixTypes names the socket types /proc/net/unix prints.
var unixTypes = map[uint64]string{1: "stream", 2: "dgram", 5: "seqpacket"}

// packetTypes names the packet socket types /proc/net/packet prints, by the
// SOCK_ number.
var packetTypes = map[uint64]string{2: "dgram", 3: "raw"}

type (
	// reader reads the sockets one /proc describes. It is a value, with the
	// root of /proc, who is asking and how to name an account, so that a test
	// can supply a /proc of its own.
	reader struct {
		proc       string
		privileged bool
		userName   func(uid string) string
	}

	// owners maps a socket's inode to the process that holds it open.
	// refused counts the processes whose descriptors this run was not
	// allowed to list, which is what makes an unmatched socket a socket
	// this run could not attribute rather than one nobody owns.
	owners struct {
		byInode map[string]owner
		refused int
	}

	// owner is a process and, where reading its executable was refused, why.
	owner struct {
		process Process
		gap     string
	}
)

// Read returns the host's sockets, every one /proc reports in every state.
// Listing them needs no privilege. Naming the process that owns one needs the
// right to read that process's descriptors, so the sockets of other users'
// processes carry a stated gap unless the run is root.
func Read(ctx context.Context) (View, error) {
	r := reader{proc: procRoot, privileged: os.Geteuid() == 0, userName: cachedAccountName()}
	sockets, err := r.read(ctx)
	if err != nil {
		return View{}, err
	}
	return NewView(sockets), nil
}

func (r reader) read(ctx context.Context) ([]Socket, error) {
	sockets, err := r.readTables()
	if err != nil {
		return nil, err
	}
	found, err := r.scanOwners(ctx)
	if err != nil {
		return nil, err
	}
	for i := range sockets {
		r.attribute(&sockets[i], found)
	}
	slices.SortFunc(sockets, compareSockets)
	return sockets, nil
}

// readTables reads every table, skipping one the kernel does not provide, as
// /proc/net/tcp6 on a host with IPv6 disabled.
func (r reader) readTables() ([]Socket, error) {
	tables := []struct {
		file  string
		parse func(r reader, lines []string) []Socket
	}{
		{"tcp", inetParser(TCP)}, {"tcp6", inetParser(TCP6)},
		{"udp", inetParser(UDP)}, {"udp6", inetParser(UDP6)},
		{"raw", inetParser(Raw)}, {"raw6", inetParser(Raw6)},
		{"unix", reader.parseUnix}, {"packet", reader.parsePacket},
	}
	var sockets []Socket
	for _, table := range tables {
		data, err := os.ReadFile(filepath.Join(r.proc, "net", table.file)) // #nosec G304 -- the path is a package constant and a fixed table name
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return nil, fmt.Errorf("sockets: read %s table: %w", table.file, err)
		}
		lines := strings.Split(string(data), "\n")
		sockets = append(sockets, table.parse(r, lines[1:])...)
	}
	return sockets, nil
}

// inetParser returns the parser for one of the tables that share the
// /proc/net/tcp layout.
func inetParser(protocol string) func(reader, []string) []Socket {
	return func(r reader, lines []string) []Socket {
		var sockets []Socket
		for _, line := range lines {
			if s, ok := r.parseInet(protocol, line); ok {
				sockets = append(sockets, s)
			}
		}
		return sockets
	}
}

// parseInet reads one line of /proc/net/{tcp,udp,raw} or their v6 forms. A
// line that does not parse is skipped: the kernel prints these tables and a
// malformed line is a kernel change this reader must not guess at.
func (r reader) parseInet(protocol, line string) (Socket, bool) {
	fields := strings.Fields(line)
	if len(fields) < inetFields {
		return Socket{}, false
	}
	local, localPort, err := parseAddress(fields[inetLocalField])
	if err != nil {
		return Socket{}, false
	}
	remote, remotePort, err := parseAddress(fields[inetRemoteField])
	if err != nil {
		return Socket{}, false
	}
	state, err := strconv.ParseUint(fields[inetStateField], hexBase, uidBits)
	if err != nil {
		return Socket{}, false
	}

	s := Socket{
		Protocol: protocol,
		State:    tcpStates[state],
		Local:    net.JoinHostPort(local.String(), strconv.Itoa(int(localPort))),
		Scope:    scopeOf(local),
		Owner:    r.userName(fields[inetUIDField]),
		Inode:    fields[inetInodeField],
	}
	if !remote.IsUnspecified() || remotePort != 0 {
		s.Remote = net.JoinHostPort(remote.String(), strconv.Itoa(int(remotePort)))
	}
	return s, true
}

// parseAddress reads the address and port the kernel prints as hex: the
// address as 32-bit words in the byte order of the host, the port as plain
// hex.
func parseAddress(field string) (net.IP, uint16, error) {
	host, port, found := strings.Cut(field, ":")
	if !found || (len(host) != ipv4Hex && len(host) != ipv6Hex) {
		return nil, 0, fmt.Errorf("sockets: malformed address %q", field)
	}
	ip := make(net.IP, len(host)/wordHex*wordBytes)
	for i := 0; i < len(host); i += wordHex {
		word, err := strconv.ParseUint(host[i:i+wordHex], hexBase, uidBits)
		if err != nil {
			return nil, 0, fmt.Errorf("sockets: malformed address %q: %w", field, err)
		}
		binary.NativeEndian.PutUint32(ip[i/wordHex*wordBytes:], uint32(word))
	}
	n, err := strconv.ParseUint(port, hexBase, portBits)
	if err != nil {
		return nil, 0, fmt.Errorf("sockets: malformed port in %q: %w", field, err)
	}
	return ip, uint16(n), nil
}

// scopeOf says which of the host's addresses a socket bound to ip answers on.
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

// parseUnix reads /proc/net/unix. A socket that has called listen is
// LISTEN, and any other takes the state the table prints. The path is the
// socket's local end, with an abstract name starting with @ as the kernel
// prints it, and is empty for a socket with no name.
func (r reader) parseUnix(lines []string) []Socket {
	var sockets []Socket
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < unixFields {
			continue
		}
		flags, err := strconv.ParseUint(fields[unixFlagsField], hexBase, uidBits)
		if err != nil {
			continue
		}
		typ, err := strconv.ParseUint(fields[unixTypeField], hexBase, uidBits)
		if err != nil {
			continue
		}
		state, err := strconv.ParseUint(fields[unixStateField], hexBase, uidBits)
		if err != nil {
			continue
		}

		s := Socket{Protocol: Unix, Type: unixTypes[typ], State: unixStates[state], Inode: fields[unixInodeField]}
		if flags&soAcceptConn != 0 {
			s.State = "LISTEN"
		}
		if len(fields) > unixPathField {
			s.Local = strings.Join(fields[unixPathField:], " ")
		}
		sockets = append(sockets, s)
	}
	return sockets
}

// parsePacket reads /proc/net/packet. A packet socket is bound to an
// interface by number, or to every interface when that is 0.
func (r reader) parsePacket(lines []string) []Socket {
	var sockets []Socket
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < packetFields {
			continue
		}
		typ, err := strconv.ParseUint(fields[packetTypeField], 10, uidBits)
		if err != nil {
			continue
		}
		index, err := strconv.Atoi(fields[packetIfaceField])
		if err != nil {
			continue
		}
		sockets = append(sockets, Socket{
			Protocol: Packet,
			Type:     packetTypes[typ],
			Local:    interfaceName(index),
			Owner:    r.userName(fields[packetUIDField]),
			Inode:    fields[packetInodeField],
		})
	}
	return sockets
}

// interfaceName names the interface with the given index, "any" for 0, and
// the index itself when no interface has it.
func interfaceName(index int) string {
	if index == 0 {
		return "any"
	}
	if iface, err := net.InterfaceByIndex(index); err == nil {
		return iface.Name
	}
	return strconv.Itoa(index)
}

// scanOwners maps every socket inode a readable process holds to that
// process. A process whose descriptors may not be listed is counted, not
// skipped silently, because an unmatched socket then may belong to it.
func (r reader) scanOwners(ctx context.Context) (owners, error) {
	found := owners{byInode: make(map[string]owner)}
	entries, err := os.ReadDir(r.proc)
	if err != nil {
		return found, fmt.Errorf("sockets: list processes: %w", err)
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return found, err
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		r.scanProcess(pid, &found)
	}
	return found, nil
}

// scanProcess records the sockets one process holds open.
func (r reader) scanProcess(pid int, found *owners) {
	dir := filepath.Join(r.proc, strconv.Itoa(pid), "fd")
	fds, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			found.refused++
		}
		return
	}
	var held *owner
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join(dir, fd.Name()))
		if err != nil || !strings.HasPrefix(target, socketLinkPrefix) {
			continue
		}
		if held == nil {
			described := r.describe(pid)
			held = &described
		}
		found.byInode[strings.TrimSuffix(strings.TrimPrefix(target, socketLinkPrefix), "]")] = *held
	}
}

// describe reads a process's name and executable. A process without an
// executable, as a kernel thread, has no path and no gap: nothing was
// refused. A path this run may not read carries the gap.
func (r reader) describe(pid int) owner {
	base := filepath.Join(r.proc, strconv.Itoa(pid))
	o := owner{process: Process{PID: pid}}
	if name, err := os.ReadFile(filepath.Join(base, "comm")); err == nil { // #nosec G304 -- the path is built from a numeric pid under the /proc root
		o.process.Name = strings.TrimSpace(string(name))
	}
	path, err := os.Readlink(filepath.Join(base, "exe"))
	switch {
	case err == nil:
		o.process.Path = path
	case errors.Is(err, fs.ErrPermission):
		o.gap = r.refusal()
	}
	return o
}

// refusal is the gap for something this run was not allowed to read: advice
// to elevate if the run is not, and a statement that elevating does not help
// if it already is.
func (r reader) refusal() string {
	if r.privileged {
		return GapUnreadable
	}
	return GapNotPermitted
}

// attribute fills in the process that owns s, or states why it cannot. A
// socket with no inode has no owner, as one in TIME_WAIT. One whose inode no
// readable process holds is unattributed only if this run was refused a
// process's descriptors, because then its owner may be one of those.
func (r reader) attribute(s *Socket, found owners) {
	if s.Inode == noInode {
		s.Gap = GapNoOwner
		return
	}
	if held, ok := found.byInode[s.Inode]; ok {
		process := held.process
		s.Process = &process
		s.Gap = held.gap
		return
	}
	if found.refused > 0 {
		s.Gap = r.refusal()
		return
	}
	s.Gap = GapNoOwner
}

// cachedAccountName returns a function that names the account with a given
// uid, or returns the uid when it has no name. Each uid is looked up once: a
// host has few accounts and many sockets, and a lookup can reach a directory
// service.
func cachedAccountName() func(uid string) string {
	names := make(map[string]string)
	return func(uid string) string {
		if name, ok := names[uid]; ok {
			return name
		}
		name := uid
		if u, err := user.LookupId(uid); err == nil {
			name = u.Username
		}
		names[uid] = name
		return name
	}
}

// compareSockets orders sockets by protocol, then local and remote end, then
// inode, so a report is the same from run to run whatever order the kernel
// listed them in.
func compareSockets(a, b Socket) int {
	return strings.Compare(
		a.Protocol+"\x00"+a.Local+"\x00"+a.Remote+"\x00"+a.Inode,
		b.Protocol+"\x00"+b.Local+"\x00"+b.Remote+"\x00"+b.Inode)
}
