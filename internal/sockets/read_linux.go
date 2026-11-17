//go:build linux

// internal/sockets/read_linux.go

package sockets

import (
	"cmp"
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

	// tcpClose is TCP_CLOSE, the state a UDP or raw socket with no peer
	// is in.
	tcpClose = 7

	// soAcceptConn is the flag the kernel sets on a unix socket that has
	// called listen, __SO_ACCEPTCON in include/uapi/linux/net.h.
	soAcceptConn = 1 << 16

	// The bases the kernel prints these tables in, and the widths of what it
	// prints: states, flags, types and address words fit 32 bits, ports 16.
	hexBase     = 16
	decimalBase = 10
	fieldBits   = 32
	portBits    = 16

	// statusEffectiveUID is the position of the effective uid among the four
	// on the Uid line of /proc/<pid>/status.
	statusEffectiveUID = 1

	socketLinkPrefix = "socket:["
	noInode          = "0"
)

// tcpStates names the kernel's TCP states by their number, from the enum in
// include/net/tcp_states.h. UDP and raw sockets print the same numbers.
var tcpStates = map[uint64]string{
	1: StateEstablished, 2: StateSynSent, 3: StateSynRecv, 4: StateFinWait1, 5: StateFinWait2,
	6: StateTimeWait, tcpClose: StateClose, 8: StateCloseWait, 9: StateLastAck, 10: StateListen,
	11: StateClosing, 12: StateNewSynRecv,
}

// unixStates names the state of a unix socket that is not listening, by the
// socket_state value /proc/net/unix prints, from include/uapi/linux/net.h.
var unixStates = map[uint64]string{
	1: StateUnconnected, 2: StateConnecting, 3: StateEstablished, 4: StateDisconnecting,
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

	// holders maps a socket's inode to the processes that hold it open.
	// refused counts the processes whose descriptors this run was not
	// allowed to list.
	holders struct {
		byInode map[string][]holder
		refused int
	}

	// holder is a process and, where reading part of it was refused, why.
	holder struct {
		process Process
		gap     string
	}
)

// Read returns the host's sockets, every one /proc reports in every state.
// Listing them needs no privilege. Naming the processes that hold one needs
// the right to read their descriptors, so a run that is not root states a gap
// for the sockets it could not attribute.
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
	found, err := r.scanHolders(ctx)
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
	state, err := strconv.ParseUint(fields[inetStateField], hexBase, fieldBits)
	if err != nil {
		return Socket{}, false
	}

	s := Socket{
		Protocol: protocol,
		State:    inetState(protocol, state),
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

// inetState names a state from an internet table. A UDP or raw socket with no
// peer is in TCP_CLOSE, which for them means bound and unconnected.
func inetState(protocol string, state uint64) string {
	if state == tcpClose && protocol != TCP && protocol != TCP6 {
		return StateUnconnected
	}
	return stateName(tcpStates, state)
}

// stateName names a state, or gives its number when it has no name.
func stateName(names map[uint64]string, state uint64) string {
	if name, ok := names[state]; ok {
		return name
	}
	return strconv.FormatUint(state, decimalBase)
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
		word, err := strconv.ParseUint(host[i:i+wordHex], hexBase, fieldBits)
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
		flags, err := strconv.ParseUint(fields[unixFlagsField], hexBase, fieldBits)
		if err != nil {
			continue
		}
		typ, err := strconv.ParseUint(fields[unixTypeField], hexBase, fieldBits)
		if err != nil {
			continue
		}
		state, err := strconv.ParseUint(fields[unixStateField], hexBase, fieldBits)
		if err != nil {
			continue
		}

		s := Socket{Protocol: Unix, Type: unixTypes[typ], State: stateName(unixStates, state), Inode: fields[unixInodeField]}
		if flags&soAcceptConn != 0 {
			s.State = StateListen
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
		typ, err := strconv.ParseUint(fields[packetTypeField], decimalBase, fieldBits)
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

// scanHolders maps every socket inode a readable process holds to the
// processes that hold it. A process whose descriptors may not be listed is
// counted, not skipped silently.
func (r reader) scanHolders(ctx context.Context) (holders, error) {
	found := holders{byInode: make(map[string][]holder)}
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

// scanProcess records the sockets one process holds open, each once however
// many of its descriptors refer to it.
func (r reader) scanProcess(pid int, found *holders) {
	dir := filepath.Join(r.proc, strconv.Itoa(pid), "fd")
	fds, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			found.refused++
		}
		return
	}
	var described *holder
	seen := make(map[string]bool)
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join(dir, fd.Name()))
		if err != nil || !strings.HasPrefix(target, socketLinkPrefix) {
			continue
		}
		inode := strings.TrimSuffix(strings.TrimPrefix(target, socketLinkPrefix), "]")
		if seen[inode] {
			continue
		}
		seen[inode] = true
		if described == nil {
			d := r.describe(pid)
			described = &d
		}
		found.byInode[inode] = append(found.byInode[inode], *described)
	}
}

// describe reads a process's name, executable and account. The account is
// the effective uid /proc/<pid>/status reports, read from the file's text
// because the ownership of the process's directory is root for a process that
// is not dumpable. A process without an executable, as a kernel thread, has no
// path and no gap: nothing was refused. A path or account this run may not
// read carries the gap.
func (r reader) describe(pid int) holder {
	base := filepath.Join(r.proc, strconv.Itoa(pid))
	h := holder{process: Process{PID: pid}}
	if name, err := os.ReadFile(filepath.Join(base, "comm")); err == nil { // #nosec G304 -- the path is built from a numeric pid under the /proc root
		h.process.Name = strings.TrimSpace(string(name))
	}
	path, err := os.Readlink(filepath.Join(base, "exe"))
	switch {
	case err == nil:
		h.process.Path = path
	case errors.Is(err, fs.ErrPermission):
		h.gap = r.refusal()
	}
	status, err := os.ReadFile(filepath.Join(base, "status")) // #nosec G304 -- the path is built from a numeric pid under the /proc root
	switch {
	case err == nil:
		if uid, ok := effectiveUID(string(status)); ok {
			h.process.User = r.userName(uid)
		}
	case errors.Is(err, fs.ErrPermission):
		h.gap = r.refusal()
	}
	return h
}

// effectiveUID returns the effective uid from the Uid line of a process's
// status text: the real, effective, saved and filesystem uids, in that order.
func effectiveUID(status string) (string, bool) {
	for _, line := range strings.Split(status, "\n") {
		if rest, found := strings.CutPrefix(line, "Uid:"); found {
			if fields := strings.Fields(rest); len(fields) > statusEffectiveUID {
				return fields[statusEffectiveUID], true
			}
		}
	}
	return "", false
}

// refusal is the gap for part of a known process this run was not allowed to
// read: advice to elevate if the run is not root, and a statement that
// elevating does not help if it already is.
func (r reader) refusal() string {
	if r.privileged {
		return GapUnreadable
	}
	return GapNotPermitted
}

// attribute fills in the processes that hold s, or states why it cannot. A
// socket with no inode has no holder, as one in TIME_WAIT. One whose inode no
// readable process holds is concluded to have none only by a root run that
// was refused nothing: a run that is not root may not see every process, as
// under hidepid, so for it the owner is undetermined.
func (r reader) attribute(s *Socket, found holders) {
	if s.Inode == noInode {
		s.Gap = GapNoOwner
		return
	}
	if held := found.byInode[s.Inode]; len(held) > 0 {
		slices.SortFunc(held, func(a, b holder) int { return cmp.Compare(a.process.PID, b.process.PID) })
		for _, h := range held {
			s.Processes = append(s.Processes, h.process)
			if s.Gap == "" {
				s.Gap = h.gap
			}
		}
		return
	}
	switch {
	case !r.privileged:
		s.Gap = GapUndetermined
	case found.refused > 0:
		s.Gap = GapUnreadable
	default:
		s.Gap = GapNoOwner
	}
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
