// internal/dataset/view_test.go

package dataset

import (
	"strings"
	"testing"
)

// Each row is written with what bears on its state, a held dataset with its
// source and license under it, and an empty store says so. A name holding a
// terminal escape is written quoted and escaped.
func TestWriteText(t *testing.T) {
	var b strings.Builder
	err := WriteText(&b, View{Store: "/store", Datasets: []Row{
		{ID: "kev", State: StateCurrent, Source: "https://data.example/kev", DataDate: "2026-11-20", Version: "2026.11.20",
			Fetched: "2026-11-22T11:00:00Z", Size: 3 << 20, License: "CC0 1.0", Attribution: "CISA"},
		{ID: "epss", State: StateNotHeld},
		{ID: "bad", State: StateUnusable, Reason: "checksum", Attention: "the import failed"},
		{ID: "old", State: StateNotApplicable, Size: 512},
		{ID: "x\x1b[2J", State: StateUnknown, Size: 1},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := `Store: /store

kev         current: data of 2026-11-20, version 2026.11.20, fetched 2026-11-22T11:00:00Z, 3.0 MiB
            source https://data.example/kev
            license CC0 1.0; CISA
epss        not held
bad         unusable: checksum
            needs attention: the import failed
old         no longer applies, 512 B
"x\x1b[2J"  unknown to this version, 1 B
`
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}

	b.Reset()
	if err := WriteText(&b, View{Store: "/store"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "the store holds none") {
		t.Errorf("an empty store gave %q", b.String())
	}
}

// An elevated run's report says, under the store, what it installed from the
// operator's store, what it left alone there and why, and the advice; a run
// with no one behind it is given the advice alone.
func TestWriteTextSaysWhatWasInstalled(t *testing.T) {
	for name, tt := range map[string]struct {
		operator *Operator
		want     string
	}{
		"installed": {&Operator{Store: "/home/a/store", Installed: []string{"epss", "kev"}},
			"Store: /store\nInstalled from /home/a/store: epss and kev\n\nkev  not held\n"},
		"refused": {&Operator{Store: "/home/a/store", Refused: []Refusal{{ID: "kev", Reason: "it is a link"}}, Advice: "run import"},
			"Store: /store\nNot installed from /home/a/store: kev: it is a link\nrun import\n\nkev  not held\n"},
		"no operator":  {&Operator{Advice: "fetch elsewhere"}, "Store: /store\nfetch elsewhere\n\nkev  not held\n"},
		"not elevated": {nil, "Store: /store\n\nkev  not held\n"},
	} {
		var b strings.Builder
		if err := WriteText(&b, View{Store: "/store", Operator: tt.operator, Datasets: []Row{{ID: "kev", State: StateNotHeld}}}); err != nil {
			t.Fatal(err)
		}
		if b.String() != tt.want {
			t.Errorf("%s: got\n%s\nwant\n%s", name, b.String(), tt.want)
		}
	}
}

func TestSize(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB", 5 << 30: "5.0 GiB"} {
		if got := Size(n); got != want {
			t.Errorf("Size(%d) = %q, want %q", n, got, want)
		}
	}
}
