//go:build windows

// internal/sockets/read_windows_test.go

package sockets

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// dword and portBytes build the fields of a row as the host lays them out: a
// DWORD in little-endian, a port in network byte order in the low 16 bits.
func dword(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func portBytes(p int) []byte { return []byte{byte(p >> 8), byte(p), 0, 0} }

func join(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// table is a count followed by rows, with the slack the host leaves after
// them.
func table(rows ...[]byte) []byte {
	return join(dword(uint32(len(rows))), join(rows...), make([]byte, 8))
}

// The tables as the host laid them out, read back as the endpoints they
// describe. The UDP IPv6 rows are two the host listed on a machine whose
// netstat showed the same ports and pids.
func TestParseTables(t *testing.T) {
	ip4 := func(a, b, c, d byte) []byte { return []byte{a, b, c, d} }

	tcp4 := table(
		join(dword(2), ip4(0, 0, 0, 0), portBytes(22), ip4(0, 0, 0, 0), portBytes(0), dword(7700)),
		join(dword(5), ip4(100, 115, 50, 102), portBytes(139), ip4(10, 0, 0, 9), portBytes(51322), dword(4)),
		join(dword(11), ip4(127, 0, 0, 1), portBytes(22), ip4(127, 0, 0, 1), portBytes(49152), dword(0)),
	)
	got := parseTCP4(tcp4)
	want := []row{
		{protocol: TCP, state: "LISTEN", local: "0.0.0.0:22", scope: ScopeWildcard, pid: 7700},
		{protocol: TCP, state: "ESTABLISHED", local: "100.115.50.102:139", remote: "10.0.0.9:51322", scope: ScopeSpecific, pid: 4},
		{protocol: TCP, state: "TIME_WAIT", local: "127.0.0.1:22", remote: "127.0.0.1:49152", scope: ScopeLoopback, pid: 0},
	}
	compareRows(t, "tcp4", got, want)

	loopback6 := net.ParseIP("::1")
	tcp6 := table(join(loopback6, dword(0), portBytes(22), make([]byte, 16), dword(0), portBytes(0), dword(2), dword(812)))
	compareRows(t, "tcp6", parseTCP6(tcp6), []row{
		{protocol: TCP6, state: "LISTEN", local: "[::1]:22", scope: ScopeLoopback, pid: 812},
	})

	compareRows(t, "udp4", parseUDP4(table(join(ip4(0, 0, 0, 0), portBytes(5353), dword(1672)))), []row{
		{protocol: UDP, state: "UNCONN", local: "0.0.0.0:5353", scope: ScopeWildcard, pid: 1672},
	})

	linkLocal := net.ParseIP("fe80::35ff:22bb:af83:9d71")
	udp6 := table(
		join(make([]byte, 16), dword(0), portBytes(500), dword(7268)),
		join(linkLocal, dword(70), portBytes(1900), dword(5460)),
	)
	compareRows(t, "udp6", parseUDP6(udp6), []row{
		{protocol: UDP6, state: "UNCONN", local: "[::]:500", scope: ScopeWildcard, pid: 7268},
		{protocol: UDP6, state: "UNCONN", local: "[fe80::35ff:22bb:af83:9d71%70]:1900", scope: ScopeSpecific, pid: 5460},
	})
}

func compareRows(t *testing.T, name string, got, want []row) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %d rows, want %d: %+v", name, len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s row %d\n got  %+v\n want %+v", name, i, got[i], want[i])
		}
	}
}

// A count larger than the buffer holds reads only the rows that are there,
// and a buffer too short for a count reads none.
func TestTableRowsAreBoundedByTheBuffer(t *testing.T) {
	short := join(dword(5), make([]byte, udp4Row))
	if got := parseUDP4(short); len(got) != 1 {
		t.Errorf("a count of 5 over one row read %d rows", len(got))
	}
	if got := parseUDP4([]byte{1}); len(got) != 0 {
		t.Errorf("a buffer shorter than a count read %d rows", len(got))
	}
}

// A socket with no owning process says so. One whose process was read keeps
// what was read and the gap for what was not, and a process owning several
// sockets is read once.
func TestReadStatesWhyAProcessIsIncomplete(t *testing.T) {
	opened := map[uint32]int{}
	r := reader{inspect: func(pid uint32, _ bool) (Process, string) {
		opened[pid]++
		if pid == 4 {
			return Process{PID: 4}, GapUnreadable
		}
		return Process{PID: int(pid), Name: "svc.exe", Path: `C:\svc.exe`, User: `NT AUTHORITY\SYSTEM`}, ""
	}}
	rows := []row{
		{protocol: TCP, state: "LISTEN", local: "0.0.0.0:80", scope: ScopeWildcard, pid: 4},
		{protocol: TCP, state: "LISTEN", local: "0.0.0.0:443", scope: ScopeWildcard, pid: 4},
		{protocol: TCP, state: "TIME_WAIT", local: "127.0.0.1:1", remote: "127.0.0.1:2", pid: 0},
		{protocol: UDP, state: "UNCONN", local: "0.0.0.0:53", pid: 900},
	}
	sockets, err := r.attribute(context.Background(), rows)
	if err != nil {
		t.Fatal(err)
	}

	if s := sockets[0]; len(s.Processes) != 1 || s.Processes[0].PID != 4 || s.Gap != GapUnreadable {
		t.Errorf("a process that could not be read: %+v", s)
	}
	if s := sockets[2]; len(s.Processes) != 0 || s.Gap != GapNoOwner {
		t.Errorf("a socket with no owner: %+v", s)
	}
	if s := sockets[3]; len(s.Processes) != 1 || s.Processes[0].User != `NT AUTHORITY\SYSTEM` || s.Gap != "" {
		t.Errorf("a process read in full: %+v", s)
	}
	if opened[4] != 1 {
		t.Errorf("the process owning two sockets was read %d times", opened[4])
	}
	if view := NewView(sockets); view.Unattributed != 2 {
		t.Errorf("unattributed = %d, want the two sockets of the unreadable process", view.Unattributed)
	}
}

// A path longer than the first buffer is read with a larger one, a query
// that fails for any other reason is not made again, and a path the longest
// buffer cannot hold is the host's error.
func TestQueryPathGrowsItsBuffer(t *testing.T) {
	long := strings.Repeat("a", 3*imagePath)
	var rooms []int
	answer := func(path string) func([]uint16, *uint32) error {
		return func(buf []uint16, size *uint32) error {
			rooms = append(rooms, len(buf))
			units := utf16.Encode([]rune(path))
			if len(units)+1 > len(buf) {
				return windows.ERROR_INSUFFICIENT_BUFFER
			}
			copy(buf, units)
			*size = uint32(len(units))
			return nil
		}
	}

	got, err := queryPath(answer(long))
	if err != nil || got != long {
		t.Errorf("a path of %d characters: %d characters, %v", len(long), len(got), err)
	}
	if want := []int{imagePath, 2 * imagePath, 4 * imagePath}; !slices.Equal(rooms, want) {
		t.Errorf("buffers of %v, want %v", rooms, want)
	}

	rooms = nil
	if got, err := queryPath(answer(`C:\Windows\System32\svchost.exe`)); err != nil || got != `C:\Windows\System32\svchost.exe` || len(rooms) != 1 {
		t.Errorf("a short path: %q, %v, after %d queries", got, err, len(rooms))
	}

	rooms = nil
	refused := func([]uint16, *uint32) error {
		rooms = append(rooms, 0)
		return windows.ERROR_ACCESS_DENIED
	}
	if _, err := queryPath(refused); !errors.Is(err, windows.ERROR_ACCESS_DENIED) || len(rooms) != 1 {
		t.Errorf("a refused query: %v, after %d queries", err, len(rooms))
	}

	rooms = nil
	if _, err := queryPath(answer(strings.Repeat("a", 2*imagePathLimit))); !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		t.Errorf("a path longer than any Windows has: %v", err)
	}
	if last := rooms[len(rooms)-1]; last != imagePathLimit {
		t.Errorf("the largest buffer tried holds %d, want %d", last, imagePathLimit)
	}
}
