// internal/sockets/text.go

package sockets

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/papa0four/orkowatch/internal/render"
)

const (
	// The tabwriter settings for the socket tables: no minimum width, no
	// tab expansion, two spaces between columns, padded with spaces.
	columnMinWidth = 0
	columnTabWidth = 0
	columnPadding  = 2
	columnPadChar  = ' '

	// none fills a column that has nothing to show, as netstat does.
	none = "-"
)

// section is one category's table: its heading as the host's own tools word
// it, its column headings, and how a socket fills a row.
type section struct {
	heading string
	columns []string
	row     func(s Socket, gap string) []string
}

// sections lists the categories in the order netstat prints them.
var sections = []struct {
	category string
	section  section
}{
	{CategoryInternet, section{
		heading: "Active Internet connections (tcp, udp)",
		columns: []string{"Proto", "State", "Local Address", "Foreign Address", "User", "PID/Program"},
		row: func(s Socket, gap string) []string {
			return []string{s.Protocol, s.State, s.Local, orNone(s.Remote), accounts(s), programs(s, gap)}
		},
	}},
	{CategoryRaw, section{
		heading: "Active raw sockets",
		columns: []string{"Proto", "State", "Local Address", "Foreign Address", "User", "PID/Program"},
		row: func(s Socket, gap string) []string {
			return []string{s.Protocol, s.State, s.Local, orNone(s.Remote), accounts(s), programs(s, gap)}
		},
	}},
	{CategoryUnix, section{
		heading: "Active UNIX domain sockets",
		columns: []string{"Proto", "Type", "State", "I-Node", "Path", "User", "PID/Program"},
		row: func(s Socket, gap string) []string {
			return []string{s.Protocol, orNone(s.Type), s.State, s.Inode, orNone(s.Local), accounts(s), programs(s, gap)}
		},
	}},
	{CategoryPacket, section{
		heading: "Active packet sockets",
		columns: []string{"Proto", "Type", "Interface", "User", "PID/Program"},
		row: func(s Socket, gap string) []string {
			return []string{s.Protocol, orNone(s.Type), s.Local, accounts(s), programs(s, gap)}
		},
	}},
}

// WriteText writes v as the tables netstat prints, one per category, with a
// footnote for each reason a socket's processes are missing, a line naming
// the categories this platform does not read, and a statement that the
// report records the remote end of every connection. It is the one text
// rendering of the sockets, used by every command that shows them. Every
// value read from the host passes through render.HostText.
func WriteText(w io.Writer, v View) error {
	ew := render.NewErrWriter(w)
	notes := newFootnotes()
	for _, entry := range sections {
		group := v.category(entry.category)
		if len(group) == 0 {
			continue
		}
		ew.Printf("%s\n", entry.section.heading)
		tw := tabwriter.NewWriter(ew, columnMinWidth, columnTabWidth, columnPadding, columnPadChar, 0)
		writeRow(tw, entry.section.columns)
		for _, s := range group {
			writeRow(tw, entry.section.row(s, notes.mark(s.Gap)))
		}
		if err := tw.Flush(); err != nil {
			return fmt.Errorf("sockets: write failed: %w", err)
		}
		ew.Printf("\n")
	}

	for i, gap := range notes.order {
		ew.Printf("[%d] %s\n", i+1, gap)
	}
	if v.Unattributed > 0 {
		ew.Printf("%d sockets not attributed to a process\n", v.Unattributed)
	}
	if len(v.NotRead) > 0 {
		ew.Printf("Not read on this platform: %s sockets\n", strings.Join(v.NotRead, ", "))
	}
	ew.Printf("This report records the remote end of every connection, and so who this host was talking to.\n")
	return ew.Err()
}

// category returns the sockets v lists under one category.
func (v View) category(name string) []Socket {
	switch name {
	case CategoryUnix:
		return v.Unix
	case CategoryRaw:
		return v.Raw
	case CategoryPacket:
		return v.Packet
	default:
		return v.Internet
	}
}

func writeRow(w io.Writer, cells []string) {
	safe := make([]string, len(cells))
	for i, cell := range cells {
		safe[i] = render.HostText(cell)
	}
	fmt.Fprintln(w, strings.Join(safe, "\t")) //nolint:errcheck // a tabwriter buffers until Flush, whose error the caller checks
}

// footnotes numbers each distinct gap in the order the tables first show it.
type footnotes struct {
	order  []string
	number map[string]int
}

func newFootnotes() *footnotes { return &footnotes{number: make(map[string]int)} }

// mark returns the reference a row shows for a gap, assigning the next number
// to a gap not seen before, and nothing for a socket with no gap.
func (f *footnotes) mark(gap string) string {
	if gap == "" {
		return ""
	}
	n, ok := f.number[gap]
	if !ok {
		f.order = append(f.order, gap)
		n = len(f.order)
		f.number[gap] = n
	}
	return "[" + strconv.Itoa(n) + "]"
}

// programs is the PID/Program column: each process holding the socket as
// pid/name, then the reference to why any are missing or incomplete.
func programs(s Socket, gap string) string {
	labels := make([]string, 0, len(s.Processes))
	for _, p := range s.Processes {
		label := strconv.Itoa(p.PID)
		if p.Name != "" {
			label += "/" + p.Name
		}
		labels = append(labels, label)
	}
	column := strings.Join(labels, ",")
	switch {
	case column == "" && gap == "":
		return none
	case column == "":
		return gap
	case gap == "":
		return column
	default:
		return column + " " + gap
	}
}

// accounts is the User column: the owner the host reports for the socket, or
// the accounts of the processes holding it where the host reports none.
func accounts(s Socket) string {
	if s.Owner != "" {
		return s.Owner
	}
	var users []string
	for _, p := range s.Processes {
		if p.User != "" && !slices.Contains(users, p.User) {
			users = append(users, p.User)
		}
	}
	if len(users) == 0 {
		return none
	}
	return strings.Join(users, ",")
}

func orNone(value string) string {
	if value == "" {
		return none
	}
	return value
}
