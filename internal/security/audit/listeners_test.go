// internal/security/audit/listeners_test.go

package audit

import (
	"context"
	"errors"
	"testing"

	"github.com/papa0four/orkowatch/internal/sockets"
)

// Sockets the caller supplied are the ones the checks get, and sockets the
// audit reads itself are read once and given to every check, or the reason
// they could not be read is.
func TestListenerSource(t *testing.T) {
	supplied := sockets.NewView([]sockets.Socket{{Protocol: sockets.TCP, State: sockets.StateListen, Local: "127.0.0.1:22", Scope: sockets.ScopeLoopback}})
	given := &listenerSource{supplied: &supplied}
	if got := given.get(context.Background()); got.View != &supplied || got.Unread != "" {
		t.Errorf("supplied sockets were not used: %+v", got)
	}

	read := &listenerSource{}
	first := read.get(context.Background())
	second := read.get(context.Background())
	if first.View != second.View || first.Unread != second.Unread {
		t.Errorf("the sockets were read more than once: %+v then %+v", first, second)
	}
	_, err := sockets.Read(context.Background())
	switch {
	case errors.Is(err, sockets.ErrUnsupported) && (first.View != nil || first.Unread != err.Error()):
		t.Errorf("on a platform whose sockets are not read: %+v", first)
	case err == nil && first.View == nil:
		t.Errorf("readable sockets were not read: %q", first.Unread)
	}
}
