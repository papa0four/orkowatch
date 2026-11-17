//go:build linux

// internal/sockets/read_linux_test.go

package sockets

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
			Socket{Protocol: TCP, State: "LISTEN", Local: "0.0.0.0:22", Scope: ScopeWildcard, Owner: "user0", Inode: "2205"}},
		{TCP, "   1: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 8277 1 0000000000000000 100 0 0 10 5",
			Socket{Protocol: TCP, State: "LISTEN", Local: "127.0.0.53:53", Scope: ScopeLoopback, Owner: "user101", Inode: "8277"}},
		{TCP, "   2: 0100007F:E00D 0100007F:9C4C 01 00000000:00000000 00:00000000 00000000  1000        0 12831 1 0000000000000000 100 0 0 10 0",
			Socket{Protocol: TCP, State: "ESTABLISHED", Local: "127.0.0.1:57357", Remote: "127.0.0.1:40012", Scope: ScopeLoopback, Owner: "user1000", Inode: "12831"}},
		{TCP, "   3: 0100007F:0016 0100007F:C000 06 00000000:00000000 03:00000000 00000000     0        0 0 3 0000000000000000",
			Socket{Protocol: TCP, State: "TIME_WAIT", Local: "127.0.0.1:22", Remote: "127.0.0.1:49152", Scope: ScopeLoopback, Owner: "user0", Inode: "0"}},
		{TCP6, "   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2207 1 0000000000000000 100 0 0 10 0",
			Socket{Protocol: TCP6, State: "LISTEN", Local: "[::1]:22", Scope: ScopeLoopback, Owner: "user0", Inode: "2207"}},
		{UDP, " 1038: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 8276 2 0000000000000000 0",
			Socket{Protocol: UDP, State: "UNCONN", Local: "127.0.0.53:53", Scope: ScopeLoopback, Owner: "user101", Inode: "8276"}},
	} {
		got, ok := r.parseInet(c.protocol, c.line)
		if !ok || got != c.want {
			t.Errorf("%s line\n got  %+v (ok %v)\n want %+v", c.protocol, got, ok, c.want)
		}
	}
}

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
		{Protocol: Unix, Type: "stream", State: "LISTEN", Local: "/run/docker.sock", Inode: "12465"},
		{Protocol: Unix, Type: "stream", State: "ESTABLISHED", Local: "/run/systemd/journal/stdout", Inode: "8298"},
		{Protocol: Unix, Type: "dgram", State: "UNCONN", Local: "@abstract", Inode: "1948"},
		{Protocol: Unix, Type: "seqpacket", State: "UNCONN", Inode: "42"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d sockets, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("socket %d\n got  %+v\n want %+v", i, got[i], want[i])
		}
	}
}

// proc builds a /proc of its own: a socket table with three sockets and the
// process that holds the first open. With refused, it also holds a process
// whose descriptors cannot be listed.
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
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	write("net/tcp", header+
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0\n"+
		"   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1 0\n"+
		"   2: 0100007F:0016 0100007F:C000 06 00000000:00000000 03:00000000 00000000     0        0 0 3 0\n")
	write("10/comm", "sshd\n")
	mkdir("10/fd")
	if err := os.Symlink("socket:[111]", filepath.Join(root, "10", "fd", "3")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/sbin/sshd", filepath.Join(root, "10", "exe")); err != nil {
		t.Fatal(err)
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

// A socket a readable process holds names that process. One no readable
// process holds is owned by nobody unless this run was refused a process's
// descriptors, when it is unattributed with the advice to elevate; and one in
// TIME_WAIT never has an owner.
func TestAttribution(t *testing.T) {
	skipBigEndian(t)

	owned := reader{proc: proc(t, false), userName: name}
	sockets, err := owned.read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s := byLocal(sockets, "0.0.0.0:22"); s.Process == nil || s.Process.PID != 10 || s.Process.Name != "sshd" || s.Process.Path != "/usr/sbin/sshd" || s.Gap != "" {
		t.Errorf("owned socket: %+v %+v", s, s.Process)
	}
	if s := byLocal(sockets, "0.0.0.0:80"); s.Process != nil || s.Gap != GapNoOwner {
		t.Errorf("socket nobody holds: %+v", s)
	}
	if s := byLocal(sockets, "127.0.0.1:22"); s.Gap != GapNoOwner {
		t.Errorf("TIME_WAIT socket: %+v", s)
	}
	if view := NewView(sockets); view.Unattributed != 0 {
		t.Errorf("unattributed = %d with every process readable", view.Unattributed)
	}

	if os.Geteuid() == 0 {
		t.Skip("root reads every process; the refusal cases need a user who may not")
	}
	refused := reader{proc: proc(t, true), userName: name}
	sockets, err = refused.read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s := byLocal(sockets, "0.0.0.0:80"); s.Gap != GapNotPermitted || !strings.Contains(s.Gap, "elevated") {
		t.Errorf("unattributed socket: %+v", s)
	}
	if s := byLocal(sockets, "127.0.0.1:22"); s.Gap != GapNoOwner {
		t.Errorf("TIME_WAIT socket after a refusal: %+v", s)
	}
	if view := NewView(sockets); view.Unattributed != 1 {
		t.Errorf("unattributed = %d, want 1", view.Unattributed)
	}

	privileged := reader{proc: refused.proc, privileged: true, userName: name}
	sockets, err = privileged.read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s := byLocal(sockets, "0.0.0.0:80"); s.Gap != GapUnreadable {
		t.Errorf("unattributed socket on an elevated run: %+v", s)
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

// Packet sockets as the kernel printed them for a raw socket bound to every
// interface and a datagram socket bound to one: the type from the SOCK_
// number, the interface by index (0 meaning every interface) and the
// descriptor's inode.
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
		if got[i] != want[i] {
			t.Errorf("socket %d\n got  %+v\n want %+v", i, got[i], want[i])
		}
	}
}
