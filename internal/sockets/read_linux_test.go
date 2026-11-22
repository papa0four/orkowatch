//go:build linux

// internal/sockets/read_linux_test.go

package sockets

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/papa0four/orkowatch/internal/elevation"
)

func skipBigEndian(t *testing.T) {
	t.Helper()
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		t.Skip("the fixture lines were printed by a little-endian host")
	}
}

func name(uid string) string { return "user" + uid }

// Lines the kernel printed, read back as the sockets they describe: the
// address in host byte order, the port in hex, the state from the kernel's
// table and the scope from the address.
func TestParseInet(t *testing.T) {
	skipBigEndian(t)
	r := reader{userName: name}
	for _, c := range []struct {
		protocol, line string
		want           Socket
	}{
		{TCP, "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2205 1 0000000000000000 100 0 0 10 0",
			Socket{Protocol: TCP, State: StateListen, Local: "0.0.0.0:22", Scope: ScopeWildcard, Owner: "user0", Inode: "2205"}},
		{TCP, "   1: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 8277 1 0000000000000000 100 0 0 10 5",
			Socket{Protocol: TCP, State: StateListen, Local: "127.0.0.53:53", Scope: ScopeLoopback, Owner: "user101", Inode: "8277"}},
		{TCP, "   2: 0100007F:E00D 0100007F:9C4C 01 00000000:00000000 00:00000000 00000000  1000        0 12831 1 0000000000000000 100 0 0 10 0",
			Socket{Protocol: TCP, State: StateEstablished, Local: "127.0.0.1:57357", Remote: "127.0.0.1:40012", Scope: ScopeLoopback, Owner: "user1000", Inode: "12831"}},
		{TCP, "   3: 0100007F:0016 0100007F:C000 06 00000000:00000000 03:00000000 00000000     0        0 0 3 0000000000000000",
			Socket{Protocol: TCP, State: StateTimeWait, Local: "127.0.0.1:22", Remote: "127.0.0.1:49152", Scope: ScopeLoopback, Owner: "user0", Inode: "0"}},
		{TCP, "   4: 0100007F:0016 0100007F:C001 07 00000000:00000000 00:00000000 00000000     0        0 77 1 0000000000000000",
			Socket{Protocol: TCP, State: StateClose, Local: "127.0.0.1:22", Remote: "127.0.0.1:49153", Scope: ScopeLoopback, Owner: "user0", Inode: "77"}},
		{TCP, "   5: 0100007F:0016 00000000:0000 63 00000000:00000000 00:00000000 00000000     0        0 78 1 0000000000000000",
			Socket{Protocol: TCP, State: "99", Local: "127.0.0.1:22", Scope: ScopeLoopback, Owner: "user0", Inode: "78"}},
		{TCP6, "   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2207 1 0000000000000000 100 0 0 10 0",
			Socket{Protocol: TCP6, State: StateListen, Local: "[::1]:22", Scope: ScopeLoopback, Owner: "user0", Inode: "2207"}},
		{TCP6, "   1: 0000000000000000FFFF00000100007F:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2208 1 0000000000000000 100 0 0 10 0",
			Socket{Protocol: TCP6, State: StateListen, Local: "127.0.0.1:80", Scope: ScopeLoopback, Owner: "user0", Inode: "2208"}},
		{UDP, " 1038: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 8276 2 0000000000000000 0",
			Socket{Protocol: UDP, State: StateUnconnected, Local: "127.0.0.53:53", Scope: ScopeLoopback, Owner: "user101", Inode: "8276"}},
	} {
		got, ok := r.parseInet(c.protocol, c.line)
		if !ok || !equalSocket(got, c.want) {
			t.Errorf("%s line\n got  %+v (ok %v)\n want %+v", c.protocol, got, ok, c.want)
		}
	}
}

func equalSocket(a, b Socket) bool { return reflect.DeepEqual(a, b) }

// A line that is not a socket line is skipped, not guessed at.
func TestParseInetSkipsMalformed(t *testing.T) {
	r := reader{userName: name}
	for _, line := range []string{"", "   sl  local_address", "0: ZZZZZZZZ:0016 00000000:0000 0A 0 0 0 0 0 0 1", "0: 0100007F:0016 0100007F 0A 0 0 0 0 0 0 1"} {
		if got, ok := r.parseInet(TCP, line); ok {
			t.Errorf("parsed %q as %+v", line, got)
		}
	}
}

// A listening unix socket is LISTEN whatever its table state, a connected one
// takes the table's state, and an abstract name keeps the @ the kernel prints.
func TestParseUnix(t *testing.T) {
	lines := []string{
		"0000000000000000: 00000002 00000000 00010000 0001 01 12465 /run/docker.sock",
		"0000000000000000: 00000003 00000000 00000000 0001 03  8298 /run/systemd/journal/stdout",
		"0000000000000000: 00000002 00000000 00000000 0002 01  1948 @abstract",
		"0000000000000000: 00000002 00000000 00000000 0005 01    42",
		"short line",
	}
	got := reader{}.parseUnix(lines)
	want := []Socket{
		{Protocol: Unix, Type: "stream", State: StateListen, Local: "/run/docker.sock", Inode: "12465"},
		{Protocol: Unix, Type: "stream", State: StateEstablished, Local: "/run/systemd/journal/stdout", Inode: "8298"},
		{Protocol: Unix, Type: "dgram", State: StateUnconnected, Local: "@abstract", Inode: "1948"},
		{Protocol: Unix, Type: "seqpacket", State: StateUnconnected, Inode: "42"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d sockets, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if !equalSocket(got[i], want[i]) {
			t.Errorf("socket %d\n got  %+v\n want %+v", i, got[i], want[i])
		}
	}
}

// Packet sockets as the kernel printed them for a raw socket bound to every
// interface and a datagram socket bound to one: the type from the SOCK_
// number, the interface by index (0 meaning every interface) and the
// descriptor's inode. The first column is the kernel's address of the socket
// and is not read.
func TestParsePacket(t *testing.T) {
	lines := []string{
		"ffff8d4ddd094000 3      3    0003   0     1 0      0      2347  ",
		"ffff8d4ddd091000 3      2    0800   99999 1 0      0      2348  ",
		"short",
	}
	got := reader{userName: name}.parsePacket(lines)
	want := []Socket{
		{Protocol: Packet, Type: "raw", Local: "any", Owner: "user0", Inode: "2347"},
		{Protocol: Packet, Type: "dgram", Local: "99999", Owner: "user0", Inode: "2348"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d sockets, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if !equalSocket(got[i], want[i]) {
			t.Errorf("socket %d\n got  %+v\n want %+v", i, got[i], want[i])
		}
	}
}

// proc builds a /proc of its own: a socket table with three sockets, two
// processes holding the first open (as a daemon and the child it forked), and,
// with refused, a process whose descriptors cannot be listed.
func proc(t *testing.T, refused bool) string {
	t.Helper()
	root := t.TempDir()
	mkdir := func(path string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(root, path), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, content string) {
		t.Helper()
		mkdir(filepath.Dir(path))
		if err := os.WriteFile(filepath.Join(root, path), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, path string) {
		t.Helper()
		mkdir(filepath.Dir(path))
		if err := os.Symlink(target, filepath.Join(root, path)); err != nil {
			t.Fatal(err)
		}
	}
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	write("net/tcp", header+
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0\n"+
		"   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1 0\n"+
		"   2: 0100007F:0016 0100007F:C000 06 00000000:00000000 03:00000000 00000000     0        0 0 3 0\n")
	for _, pid := range []string{"30", "10"} {
		write(pid+"/comm", "sshd\n")
		write(pid+"/status", "Name:\tsshd\nUid:\t1000\t0\t1000\t0\nGid:\t0\t0\t0\t0\n")
		link("/usr/sbin/sshd", pid+"/exe")
		link("socket:[111]", pid+"/fd/3")
		link("socket:[111]", pid+"/fd/4")
	}
	if refused {
		mkdir("20/fd")
		if err := os.Chmod(filepath.Join(root, "20", "fd"), 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Chmod(filepath.Join(root, "20", "fd"), 0o750); err != nil {
				t.Error(err)
			}
		})
	}
	return root
}

func byLocal(sockets []Socket, local string) Socket {
	for _, s := range sockets {
		if s.Local == local {
			return s
		}
	}
	return Socket{}
}

func readOrFail(t *testing.T, r reader) []Socket {
	t.Helper()
	sockets, err := r.read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return sockets
}

// Every process holding a socket is named, each once, in pid order. A socket
// in TIME_WAIT has no holder on any run. A socket no readable process holds
// has no owner only on a root run that was refused nothing; a run that is not
// root may not see every process, so for it the owner is undetermined; and a
// root run that was refused a process cannot conclude either.
func TestAttribution(t *testing.T) {
	skipBigEndian(t)

	user := readOrFail(t, reader{proc: proc(t, false), userName: name})
	held := byLocal(user, "0.0.0.0:22")
	if len(held.Processes) != 2 || held.Processes[0].PID != 10 || held.Processes[1].PID != 30 || held.Gap != "" {
		t.Errorf("a socket two processes hold: %+v", held)
	}
	if p := held.Processes[0]; p.Name != "sshd" || p.Path != "/usr/sbin/sshd" || p.User != "user0" {
		t.Errorf("a holder read in full: %+v", p)
	}
	if s := byLocal(user, "0.0.0.0:80"); len(s.Processes) != 0 || s.Gap != GapUndetermined {
		t.Errorf("a socket no visible process holds, on a run that is not root: %+v", s)
	}
	if s := byLocal(user, "127.0.0.1:22"); s.Gap != GapNoOwner {
		t.Errorf("a socket in TIME_WAIT: %+v", s)
	}
	if view := NewView(user); view.Unattributed != 1 {
		t.Errorf("unattributed = %d, want 1", view.Unattributed)
	}

	root := readOrFail(t, reader{proc: proc(t, false), privileged: true, userName: name})
	if s := byLocal(root, "0.0.0.0:80"); s.Gap != GapNoOwner {
		t.Errorf("a socket no process holds, on a root run refused nothing: %+v", s)
	}

	if elevation.Elevated() {
		t.Skip("root reads every directory; the refusal case needs a user who may not")
	}
	refusedRoot := readOrFail(t, reader{proc: proc(t, true), privileged: true, userName: name})
	if s := byLocal(refusedRoot, "0.0.0.0:80"); s.Gap != GapUnreadable {
		t.Errorf("a socket no readable process holds, on a root run refused a process: %+v", s)
	}
}

// A table the kernel does not provide is skipped, and a cancelled run stops.
func TestReadSkipsMissingTablesAndStopsWhenCancelled(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o750); err != nil {
		t.Fatal(err)
	}
	r := reader{proc: root, userName: name}
	if sockets, err := r.read(context.Background()); err != nil || len(sockets) != 0 {
		t.Errorf("empty /proc: %v %v", sockets, err)
	}
	if err := os.WriteFile(filepath.Join(root, "1"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.read(ctx); err == nil {
		t.Error("a cancelled run read to the end")
	}
}
