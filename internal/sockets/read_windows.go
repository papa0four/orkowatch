//go:build windows

// internal/sockets/read_windows.go

package sockets

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	afInet  = 2
	afInet6 = 23

	// The table classes that return the owning process id of every TCP
	// endpoint and of every UDP endpoint, from GetExtendedTcpTable and
	// GetExtendedUdpTable.
	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1

	// A table is a count of rows followed by the rows. The size of a row is
	// that of its MIB_*ROW_OWNER_PID structure.
	tableHeader = 4
	tcp4Row     = 24
	tcp6Row     = 56
	udp4Row     = 12
	udp6Row     = 28

	// fetchAttempts bounds the retries when the table grows between the
	// call that sizes it and the call that reads it.
	fetchAttempts = 5

	// tableSlack is room beyond the size the host reports, so a row added
	// between the two calls does not make the second one fail.
	tableSlack = 4096

	addressV4 = 4
	addressV6 = 16
	imagePath = 1024

	decimalBase = 10

	// tcpListen is MIB_TCP_STATE_LISTEN.
	tcpListen = 2
)

// tcpStates names the MIB_TCP_STATE values, from the TCP row pages of the
// IP Helper documentation, in the words the package declares for every
// platform.
var tcpStates = map[uint32]string{
	1: StateClose, tcpListen: StateListen, 3: StateSynSent, 4: StateSynRecv, 5: StateEstablished,
	6: StateFinWait1, 7: StateFinWait2, 8: StateCloseWait, 9: StateClosing, 10: StateLastAck,
	11: StateTimeWait, 12: StateDeleteTCB,
}

var (
	iphlpapi   = windows.NewLazySystemDLL("iphlpapi.dll")
	procTCPGet = iphlpapi.NewProc("GetExtendedTcpTable")
	procUDPGet = iphlpapi.NewProc("GetExtendedUdpTable")
)

// notRead lists the categories the owner-pid tables do not cover.
func notRead() []string { return []string{CategoryUnix, CategoryRaw, CategoryPacket} }

type (
	// row is one endpoint as a table reports it, before its process is read.
	row struct {
		protocol string
		state    string
		local    string
		remote   string
		scope    string
		pid      uint32
	}

	// reader reads the sockets the host's tables list. inspect reads one
	// process, so a test can supply the processes.
	reader struct {
		elevated bool
		inspect  func(pid uint32, elevated bool) (Process, string)
	}
)

// Read returns the host's TCP and UDP sockets over IPv4 and IPv6. Listing
// them needs no privilege. Reading the process that owns one needs the right
// to open it, so processes of other users carry a stated gap unless the run is
// elevated. Unix-domain, raw and packet sockets are not in these tables and
// are listed in NotRead.
func Read(ctx context.Context) (View, error) {
	r := reader{elevated: administrator(), inspect: inspectProcess}
	sockets, err := r.read(ctx)
	if err != nil {
		return View{}, err
	}
	view := NewView(sockets)
	view.NotRead = notRead()
	return view, nil
}

// administrator reports whether the run holds the Administrators group in
// effect, which is what an elevated run adds. The token's elevation flag is
// not used: a token restricted from an elevated one, as runas /trustlevel
// makes, still reports elevated while its Administrators group is deny-only.
// When membership cannot be checked the run is taken as not administrator, so
// a refusal advises elevating rather than claiming elevation would not help.
func administrator() bool {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	member, err := windows.Token(0).IsMember(admins)
	return err == nil && member
}

func (r reader) read(ctx context.Context) ([]Socket, error) {
	var rows []row
	for _, table := range []struct {
		proc  *windows.LazyProc
		af    uintptr
		class uintptr
		parse func([]byte) []row
	}{
		{procTCPGet, afInet, tcpTableOwnerPIDAll, parseTCP4},
		{procTCPGet, afInet6, tcpTableOwnerPIDAll, parseTCP6},
		{procUDPGet, afInet, udpTableOwnerPID, parseUDP4},
		{procUDPGet, afInet6, udpTableOwnerPID, parseUDP6},
	} {
		data, err := fetchTable(table.proc, table.af, table.class)
		if err != nil {
			return nil, err
		}
		rows = append(rows, table.parse(data)...)
	}

	sockets, err := r.attribute(ctx, rows)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(sockets, compareSockets)
	return sockets, nil
}

// attribute turns rows into sockets and names the process that holds each. A
// pid of 0 is no process at all, as for a socket in TIME_WAIT. A process that
// holds several sockets is read once.
func (r reader) attribute(ctx context.Context, rows []row) ([]Socket, error) {
	processes := make(map[uint32]described)
	sockets := make([]Socket, 0, len(rows))
	for _, rw := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s := Socket{Protocol: rw.protocol, State: rw.state, Local: rw.local, Remote: rw.remote, Scope: rw.scope}
		if rw.pid == 0 {
			s.Gap = GapNoOwner
		} else {
			held, ok := processes[rw.pid]
			if !ok {
				held.process, held.gap = r.inspect(rw.pid, r.elevated)
				processes[rw.pid] = held
			}
			s.Processes, s.Gap = []Process{held.process}, held.gap
		}
		sockets = append(sockets, s)
	}
	return sockets, nil
}

// described is a process as read, with why it is incomplete, kept so a
// process owning many sockets is opened once.
type described struct {
	process Process
	gap     string
}

// fetchTable reads one table, sizing it first and trying again if it grew in
// between, as a busy host's tables do.
func fetchTable(proc *windows.LazyProc, af, class uintptr) ([]byte, error) {
	// A call with no buffer answers with the size the table needs, as
	// ERROR_INSUFFICIENT_BUFFER; any other failure is the table's own.
	var size uint32
	sizing, _, _ := proc.Call( //nolint:errcheck // the third result is GetLastError, which this API does not set; the status carries the outcome
		0,
		uintptr(unsafe.Pointer(&size)), // #nosec G103 -- out parameter receiving the size the table needs
		0, af, class, 0)
	if errno := windows.Errno(sizing); errno != 0 && errno != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, fmt.Errorf("sockets: size socket table: %w", errno)
	}
	for range fetchAttempts {
		got := size + tableSlack
		buf := make([]byte, got)
		status, _, _ := proc.Call( //nolint:errcheck // the third result is GetLastError, which this API does not set; status carries the outcome
			uintptr(unsafe.Pointer(&buf[0])), // #nosec G103 -- out parameter receiving the table for the duration of the call
			uintptr(unsafe.Pointer(&got)),    // #nosec G103 -- in and out parameter holding the buffer's size
			0, af, class, 0)
		switch windows.Errno(status) {
		case 0:
			return buf[:got], nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			size = got
		default:
			return nil, fmt.Errorf("sockets: read socket table: %w", windows.Errno(status))
		}
	}
	return nil, errors.New("sockets: socket table kept growing while it was read")
}

// tableRows returns the rows of a table of rowSize-byte rows, as many as its count
// says and the buffer holds.
func tableRows(data []byte, rowSize int) [][]byte {
	if len(data) < tableHeader {
		return nil
	}
	n := min(int(binary.LittleEndian.Uint32(data)), (len(data)-tableHeader)/rowSize)
	out := make([][]byte, n)
	for i := range out {
		start := tableHeader + i*rowSize
		out[i] = data[start : start+rowSize]
	}
	return out
}

// port reads a port, which a row holds in network byte order in the low 16
// bits of a DWORD.
func port(b []byte) int { return int(b[0])<<8 | int(b[1]) }

func word(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

// endpoint joins an address and port, with the scope id of an IPv6 address
// that has one, as netstat prints it.
func endpoint(ip net.IP, scope uint32, portNumber int) string {
	host := ip.String()
	if scope != 0 {
		host += "%" + strconv.FormatUint(uint64(scope), decimalBase)
	}
	return net.JoinHostPort(host, strconv.Itoa(portNumber))
}

func stateName(state uint32) string {
	if name, ok := tcpStates[state]; ok {
		return name
	}
	return strconv.FormatUint(uint64(state), decimalBase)
}

// remoteEnd is the peer of a connected TCP endpoint, empty for one that has
// none: the table gives no meaning to the remote end of a listener.
func remoteEnd(state uint32, ip net.IP, scope uint32, portNumber int) string {
	if state == tcpListen {
		return ""
	}
	return endpoint(ip, scope, portNumber)
}

// parseTCP4 reads MIB_TCPTABLE_OWNER_PID: state, local address and port,
// remote address and port, owning pid, each a DWORD.
func parseTCP4(data []byte) []row {
	var out []row
	for _, b := range tableRows(data, tcp4Row) {
		state := word(b)
		local := net.IP(b[4 : 4+addressV4])
		remote := net.IP(b[12 : 12+addressV4])
		out = append(out, row{
			protocol: TCP,
			state:    stateName(state),
			local:    endpoint(local, 0, port(b[8:])),
			remote:   remoteEnd(state, remote, 0, port(b[16:])),
			scope:    scopeOf(local),
			pid:      word(b[20:]),
		})
	}
	return out
}

// parseTCP6 reads MIB_TCP6TABLE_OWNER_PID: local address, scope id and port,
// remote address, scope id and port, state, owning pid.
func parseTCP6(data []byte) []row {
	var out []row
	for _, b := range tableRows(data, tcp6Row) {
		state := word(b[48:])
		local := net.IP(b[0:addressV6])
		remote := net.IP(b[24 : 24+addressV6])
		out = append(out, row{
			protocol: TCP6,
			state:    stateName(state),
			local:    endpoint(local, word(b[16:]), port(b[20:])),
			remote:   remoteEnd(state, remote, word(b[40:]), port(b[44:])),
			scope:    scopeOf(local),
			pid:      word(b[52:]),
		})
	}
	return out
}

// parseUDP4 reads MIB_UDPTABLE_OWNER_PID: local address, port, owning pid. A
// UDP endpoint has no state and no peer, so it is reported as the bound,
// unconnected socket it is.
func parseUDP4(data []byte) []row {
	var out []row
	for _, b := range tableRows(data, udp4Row) {
		local := net.IP(b[0:addressV4])
		out = append(out, row{
			protocol: UDP,
			state:    StateUnconnected,
			local:    endpoint(local, 0, port(b[4:])),
			scope:    scopeOf(local),
			pid:      word(b[8:]),
		})
	}
	return out
}

// parseUDP6 reads MIB_UDP6TABLE_OWNER_PID: local address, scope id, port,
// owning pid.
func parseUDP6(data []byte) []row {
	var out []row
	for _, b := range tableRows(data, udp6Row) {
		local := net.IP(b[0:addressV6])
		out = append(out, row{
			protocol: UDP6,
			state:    StateUnconnected,
			local:    endpoint(local, word(b[16:]), port(b[20:])),
			scope:    scopeOf(local),
			pid:      word(b[24:]),
		})
	}
	return out
}

// inspectProcess reads the process with the given pid: its executable and the
// account it runs as. The pid is known without privilege, so the process
// always carries it. Opening the process or its token can be refused, and a
// refusal is stated: advice to elevate if the run is not elevated, and a
// statement that elevating does not help if it is, as for the System process.
// A pid that no longer names a process means it ended; any other failure is
// stated with the error the host gave.
func inspectProcess(pid uint32, elevated bool) (Process, string) {
	process := Process{PID: int(pid)}
	refusal := GapNotPermitted
	if elevated {
		refusal = GapUnreadable
	}

	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return process, refusal
	case errors.Is(err, windows.ERROR_INVALID_PARAMETER):
		return process, GapExited
	case err != nil:
		return process, "process could not be opened: " + err.Error()
	}
	defer windows.CloseHandle(handle) //nolint:errcheck // a handle opened for query; its close error changes nothing this run reports

	var gap string
	note := func(what string, err error) {
		switch {
		case gap != "":
		case errors.Is(err, windows.ERROR_ACCESS_DENIED):
			gap = refusal
		default:
			gap = what + " could not be read: " + err.Error()
		}
	}
	if path, err := imageName(handle); err == nil {
		process.Path = path
		process.Name = filepath.Base(path)
	} else {
		note("executable", err)
	}
	if user, err := tokenAccount(handle); err == nil {
		process.User = user
	} else {
		note("account", err)
	}
	return process, gap
}

// imageName returns the path of the executable a process was started from.
func imageName(handle windows.Handle) (string, error) {
	buf := make([]uint16, imagePath)
	size := uint32(imagePath)
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}

// tokenAccount returns the account a process runs as, as DOMAIN\name, or its
// SID when no name resolves.
func tokenAccount(handle windows.Handle) (string, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err != nil {
		return "", err
	}
	defer token.Close() //nolint:errcheck // a token opened for query; its close error changes nothing this run reports

	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	account, domain, _, err := user.User.Sid.LookupAccount("")
	if err != nil {
		return user.User.Sid.String(), nil
	}
	if domain == "" {
		return account, nil
	}
	return domain + `\` + account, nil
}
