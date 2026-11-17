// cmd/commands/listeners_test.go

package cmd

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/papa0four/orkowatch/cmd/commands/delivery"
	"github.com/papa0four/orkowatch/internal/sockets"
	"github.com/papa0four/orkowatch/internal/tui"
)

func listenersRun() allReport {
	view := sockets.NewView([]sockets.Socket{
		{Protocol: sockets.TCP, State: sockets.StateListen, Local: "0.0.0.0:22", Scope: sockets.ScopeWildcard, Owner: "root",
			Processes: []sockets.Process{{PID: 10, Name: "sshd", Path: "/usr/sbin/sshd", User: "root"}, {PID: 30, Name: "sshd"}}},
		{Protocol: sockets.TCP, State: sockets.StateEstablished, Local: "10.0.0.5:22", Remote: "10.0.0.9:51322", Gap: sockets.GapUndetermined},
		{Protocol: sockets.Unix, Type: "stream", State: sockets.StateListen, Inode: "42"},
	})
	view.NotRead = []string{sockets.CategoryPacket}
	return allReport{title: "owatch listeners", result: &ScanResult{
		Timestamp: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC),
		Modules:   []moduleRun{inventoryModule("listeners")},
		Sockets:   &view,
	}}
}

func socketsTabOf(t *testing.T, report tui.Report) tui.Tab {
	t.Helper()
	for _, tab := range report.Tabs {
		if tab.ID == tui.TabSockets {
			return tab
		}
	}
	t.Fatalf("no sockets tab in %+v", report.Tabs)
	return tui.Tab{}
}

// A run of the listeners module opens on its sockets, one record per socket
// with every holder and the reason any is missing, and a report saved as JSON
// or YAML opens to the same records.
func TestListenersBrowseParity(t *testing.T) {
	run := listenersRun()
	live := run.Browse("")
	if live.Start != tui.TabSockets {
		t.Errorf("a listeners run opens on %q", live.Start)
	}
	tab := socketsTabOf(t, live)
	if len(tab.Records) != 3 || !strings.Contains(tab.Note, "packet") {
		t.Fatalf("the sockets tab: %+v", tab)
	}
	joined := fieldsText(tab.Records[0].Fields)
	for _, want := range []string{"process=10  sshd  /usr/sbin/sshd  root", "process=30  sshd", "scope=wildcard"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the first record lacks %q:\n%s", want, joined)
		}
	}
	if gap := tab.Records[1].Fields; !strings.Contains(fieldsText(gap), "not attributed="+sockets.GapUndetermined) {
		t.Errorf("the unattributed record does not say why: %s", fieldsText(gap))
	}
	if tab.Records[2].Title != "unnamed, inode 42" {
		t.Errorf("an unnamed unix socket is titled %q", tab.Records[2].Title)
	}

	for _, format := range []delivery.Format{delivery.FormatJSON, delivery.FormatYAML} {
		var data []byte
		var err error
		if format == delivery.FormatJSON {
			data, err = json.Marshal(run.View())
		} else {
			data, err = yaml.Marshal(run.View())
		}
		if err != nil {
			t.Fatal(err)
		}
		saved, err := decodeReport("saved."+format.Extension(), format, delivery.FormatText, data)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if got := socketsTabOf(t, saved); !reflect.DeepEqual(got, tab) {
			t.Errorf("%s: the saved report's sockets tab differs from the live run's\n got  %+v\n want %+v", format, got, tab)
		}
		if saved.Start != tui.TabSockets {
			t.Errorf("%s: a saved listeners report opens on %q", format, saved.Start)
		}
	}
}

func fieldsText(fields []tui.SummaryLine) string {
	var lines []string
	for _, f := range fields {
		lines = append(lines, f.Label+"="+f.Value)
	}
	return strings.Join(lines, "\n")
}

// The plain text of a listeners run is the sockets tables alone, as the
// software command's is its package list.
func TestListenersText(t *testing.T) {
	var out strings.Builder
	if err := listenersRun().WriteText(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "Active Internet connections") {
		t.Errorf("the listeners text:\n%s", out.String())
	}
}
