// internal/sockets/text_test.go

package sockets

import (
	"slices"
	"strings"
	"testing"
)

// The tables are laid out as netstat lays them out: a heading per category,
// columns aligned under their headings, every holder of a socket named, a
// footnote for each reason a holder is missing, the categories a platform
// does not read named, and the statement that remote peers are recorded. A
// path from the host that holds a newline cannot forge a line.
func TestWriteText(t *testing.T) {
	v := NewView([]Socket{
		{Protocol: TCP, State: StateListen, Local: "0.0.0.0:22", Scope: ScopeWildcard, Owner: "root",
			Processes: []Process{{PID: 10, Name: "sshd"}, {PID: 30, Name: "sshd"}}},
		{Protocol: TCP, State: StateEstablished, Local: "10.0.0.5:22", Remote: "10.0.0.9:51322", Owner: "root", Gap: GapUndetermined},
		{Protocol: TCP, State: StateTimeWait, Local: "127.0.0.1:22", Remote: "127.0.0.1:49152", Gap: GapNoOwner},
		{Protocol: Unix, Type: "stream", State: StateListen, Local: "/run/evil\nforged line", Inode: "12465",
			Processes: []Process{{PID: 4, User: `NT AUTHORITY\SYSTEM`}}, Gap: GapUnreadable},
	})
	v.NotRead = []string{CategoryRaw, CategoryPacket}

	var out strings.Builder
	if err := WriteText(&out, v); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	lines := strings.Split(text, "\n")

	for _, want := range []string{
		"Active Internet connections (tcp, udp)",
		"Active UNIX domain sockets",
		"10/sshd,30/sshd",
		"root  [1]",
		"[1] " + GapUndetermined,
		"[2] " + GapNoOwner,
		"[3] " + GapUnreadable,
		"4 [3]",
		`NT AUTHORITY\SYSTEM`,
		"2 sockets not attributed to a process",
		"Not read on this platform: raw, packet sockets",
		"records the remote end of every connection",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the text lacks %q:\n%s", want, text)
		}
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "forged line") {
			t.Errorf("a path with a newline forged a line:\n%s", text)
		}
	}

	header := lines[1]
	for _, line := range lines[2:5] {
		for _, column := range []string{"State", "Local Address", "PID/Program"} {
			at := strings.Index(header, column)
			if at < 0 || len(line) <= at || line[at-1] != ' ' || line[at] == ' ' {
				t.Errorf("a row is not aligned under %q:\n%s\n%s", column, header, line)
			}
		}
	}
}

// A view with no sockets prints no tables, only what was not read and the
// disclosure.
func TestWriteTextEmpty(t *testing.T) {
	var out strings.Builder
	if err := WriteText(&out, View{NotRead: []string{CategoryUnix}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "Active") || !strings.Contains(out.String(), "Not read on this platform: unix sockets") {
		t.Errorf("an empty view:\n%s", out.String())
	}
}

// Sockets are ordered by protocol, then address, then port as a number.
func TestCompareSocketsOrdersPortsByNumber(t *testing.T) {
	sockets := []Socket{
		{Protocol: TCP, Local: "0.0.0.0:445"}, {Protocol: TCP, Local: "0.0.0.0:22"},
		{Protocol: TCP, Local: "0.0.0.0:135"}, {Protocol: Unix, Local: "/run/b"}, {Protocol: Unix, Local: "/run/a"},
	}
	slices.SortFunc(sockets, compareSockets)
	var got []string
	for _, s := range sockets {
		got = append(got, s.Local)
	}
	if want := []string{"0.0.0.0:22", "0.0.0.0:135", "0.0.0.0:445", "/run/a", "/run/b"}; !slices.Equal(got, want) {
		t.Errorf("order %v, want %v", got, want)
	}
}
