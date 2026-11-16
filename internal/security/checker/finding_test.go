// internal/security/checker/finding_test.go

package checker

import "testing"

// The evidence helper keeps facts in the order given and leaves out one with
// no value.
func TestEvidenceOmitsEmptyFacts(t *testing.T) {
	got := evidence(kindFile, "/x", fact(factMode, "-rw-r--r--"), fact(factReach, ""), fact(factUID, "0"))
	if len(got.Facts) != 2 || got.Facts[0].Name != string(factMode) || got.Facts[1].Name != string(factUID) {
		t.Errorf("facts = %v", got.Facts)
	}
}
