// internal/security/finding/fact_test.go

package finding

import "testing"

// An enumerated fact takes only its own values, any other fact takes whatever
// was observed, and a name or kind no checker records is not known.
func TestFactVocabulary(t *testing.T) {
	if !FactReach.Takes(ReachRootOnly) || FactReach.Takes("everyone") {
		t.Error("reach does not take exactly its own values")
	}
	if !FactLocation.Takes(LocationHome) || FactLocation.Takes("/home") {
		t.Error("location does not take exactly its own values")
	}
	if !FactUID.Takes("1000") || !FactUID.Takes("everyone") {
		t.Error("uid is not free-form")
	}
	if FactName("reech").Known() || FactName("reech").Takes("") {
		t.Error("an unknown fact name is accepted")
	}
	if !KindFile.Known() || EvidenceKind("fiel").Known() {
		t.Error("evidence kinds are not recognized exactly")
	}
	for name := range factValues {
		if !name.Known() {
			t.Errorf("%s is declared and not known", name)
		}
	}
}
