// internal/dataset/view_test.go

package dataset

import (
	"strings"
	"testing"
)

// Each row is written with what bears on its state, a held dataset with its
// source and license under it, and an empty store says so.
func TestWriteText(t *testing.T) {
	var b strings.Builder
	err := WriteText(&b, View{Store: "/store", Datasets: []Row{
		{ID: "kev", State: StateCurrent, Source: "https://data.example/kev", DataDate: "2026-11-20",
			Fetched: "2026-11-22T11:00:00Z", Size: 3 << 20, License: "CC0 1.0", Attribution: "CISA"},
		{ID: "epss", State: StateNotHeld},
		{ID: "bad", State: StateUnusable, Reason: "checksum"},
		{ID: "old", State: StateNotApplicable, Size: 512},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := `Store: /store

"kev"   current: data of 2026-11-20, fetched 2026-11-22T11:00:00Z, 3.0 MiB
        source https://data.example/kev
        license CC0 1.0; CISA
"epss"  not held
"bad"   unusable: checksum
"old"   no longer applies, 512 B
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

func TestSize(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB", 5 << 30: "5.0 GiB"} {
		if got := Size(n); got != want {
			t.Errorf("Size(%d) = %q, want %q", n, got, want)
		}
	}
}
