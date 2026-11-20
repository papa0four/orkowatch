// internal/security/checker/includes_test.go

package checker

import (
	"slices"
	"testing"
)

// A file is entered once while it is being read: entering it again is
// refused and leaves the chain as it was, and leaving a file lets it be
// entered again, as a file included twice from different places is.
func TestIncludeChain(t *testing.T) {
	var chain includeChain

	leaveA, ok := chain.enter("a")
	if !ok {
		t.Fatal("the first file was refused")
	}
	leaveB, ok := chain.enter("b")
	if !ok {
		t.Fatal("a file not being read was refused")
	}
	if _, ok := chain.enter("a"); ok {
		t.Error("a file already being read was entered again")
	}
	if want := (includeChain{"a", "b"}); !slices.Equal(chain, want) {
		t.Errorf("after a refusal the chain is %q, want %q", chain, want)
	}

	leaveB()
	leaveB, ok = chain.enter("b")
	if !ok {
		t.Error("a file that was left could not be entered again")
	}
	leaveB()
	leaveA()
	if len(chain) != 0 {
		t.Errorf("after every file was left the chain is %q", chain)
	}
}
