// cmd/commands/delivery/delivery_test.go

package delivery

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/internal/tui"
)

// sample is a report whose view and text are known.
type sample struct{}

func (sample) View() any                   { return map[string]int{"count": 2} }
func (sample) WriteText(w io.Writer) error { _, err := io.WriteString(w, "count 2\n"); return err }

// flags are the output flags of a command given args, resolved.
func flags(t *testing.T, args ...string) *Flags {
	t.Helper()
	cmd := &cobra.Command{Use: "probe", RunE: func(*cobra.Command, []string) error { return nil }}
	f := Bind(cmd)
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatal(err)
	}
	if err := f.Resolve(cmd); err != nil {
		t.Fatal(err)
	}
	return f
}

// The payload is the report in the format resolved: its text by default, and
// its view encoded for -o json and -o yaml, as Deliver writes it and as the
// browser shows it under t.
func TestPayload(t *testing.T) {
	for name, c := range map[string]struct {
		args []string
		want func() ([]byte, error)
	}{
		"text": {nil, func() ([]byte, error) { return []byte("count 2\n"), nil }},
		"json": {[]string{"-o", "json"}, func() ([]byte, error) { return Encode(sample{}.View(), FormatJSON) }},
		"yaml": {[]string{"-o", "yaml"}, func() ([]byte, error) { return Encode(sample{}.View(), FormatYAML) }},
	} {
		want, err := c.want()
		if err != nil {
			t.Fatal(err)
		}
		if got, err := flags(t, c.args...).Payload(sample{}); err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: %q, %v, want %q", name, got, err, want)
		}
	}
}

// A browser closed by a refresh it cannot make prints what to run instead
// and is not an error; any other error of the browser is.
func TestBrowseLeaves(t *testing.T) {
	var said bytes.Buffer
	leave := func(tui.Report) error {
		return tui.Leave{Text: "Run owatch data refresh. Then run this command again."}
	}
	if err := browseWith(leave, &said)(tui.Report{}); err != nil || said.String() != "Run owatch data refresh. Then run this command again.\n" {
		t.Errorf("a leave gave %v and printed %q", err, said.String())
	}
	broken := errors.New("no terminal")
	said.Reset()
	if err := browseWith(func(tui.Report) error { return broken }, &said)(tui.Report{}); !errors.Is(err, broken) || said.Len() > 0 {
		t.Errorf("a failure gave %v and printed %q", err, said.String())
	}
}
