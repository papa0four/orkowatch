// internal/security/checker/finding.go

package checker

import (
	"fmt"

	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/security/types"
)

// Evidence kinds: what sort of thing an evidence subject is. Not every kind
// is produced on every platform, and a constant no build references compiles
// away.
const (
	kindFile      = "file"
	kindAccount   = "account"
	kindDirective = "sshd-directive"
	kindManager   = "firewall-manager"
	kindProfile   = "firewall-profile"
	kindService   = "service"
	kindACL       = "acl-entry"
	kindShare     = "share"
	kindSetting   = "setting"

	// factPair is the name and value one fact consists of.
	factPair = 2
)

// report accumulates one check's outcome: a condition per rule the check
// evaluated, and the narration that belongs to none of them. It is the single
// path by which a checker records a result, so a rule is concluded once
// however many subjects tripped it, and a check's own result is always the
// aggregate of its conditions.
type report struct {
	osCtx  registry.OSContext
	result types.AuditResult
	index  map[registry.FindingKey]int
}

func newReport(id checkIdentity) *report {
	return &report{
		osCtx: id.osCtx,
		result: types.AuditResult{
			Name:        id.Name(),
			Description: id.Description(),
		},
		index: make(map[registry.FindingKey]int),
	}
}

// note appends one line of narration: what the check did or saw that is not
// the outcome of any rule.
func (r *report) note(symbol, format string, args ...any) {
	r.result.Details = append(r.result.Details, symbol+" "+fmt.Sprintf(format, args...))
}

// section starts a titled block of narration.
func (r *report) section(title string) {
	r.result.Details = append(r.result.Details, "", title)
}

// lines appends narration a tool produced, verbatim.
func (r *report) lines(lines ...string) {
	r.result.Details = append(r.result.Details, lines...)
}

// observed records that the condition key defines was seen on the subjects
// in evidence. The definition decides what that means: fail for most, and
// notapplicable for one describing a state the rule does not cover. A key
// with no definition is a defect in the checker or the data file, not a host
// condition, so it panics rather than letting a detected condition report
// clean.
func (r *report) observed(key registry.FindingKey, evidence ...types.Evidence) {
	if i, ok := r.index[key]; ok && r.result.Conditions[i].Finding != nil {
		r.result.Conditions[i].Evidence = append(r.result.Conditions[i].Evidence, evidence...)
		return
	}

	def, ok := registry.Lookup(r.osCtx, key)
	if !ok {
		panic("checker: no registry definition for finding key " + string(key) + " on platform " + string(r.osCtx.Platform))
	}

	condition := types.Condition{
		Key:      string(key),
		Result:   def.Result,
		Finding:  def.Finding(),
		Evidence: evidence,
	}
	if def.Result.NeedsReason() {
		condition.Reason = def.Title
	}
	r.record(key, condition)
}

// pass records that each rule was evaluated and holds. A rule already
// concluded otherwise keeps that conclusion. The empty key is ignored, which
// is how a platform that defines no rule for a condition opts out of it.
func (r *report) pass(keys ...registry.FindingKey) {
	for _, key := range keys {
		r.record(key, types.Condition{Key: string(key), Result: types.ResultPass})
	}
}

// inconclusive records that each rule produced no judgment, and why. The
// reason is mandatory: a result that is neither pass nor fail tells the
// operator nothing without it, so omitting one is a defect in the checker.
func (r *report) inconclusive(result types.Result, reason string, keys ...registry.FindingKey) {
	if !result.NeedsReason() || reason == "" {
		panic("checker: inconclusive result " + string(result) + " recorded without a reason")
	}
	for _, key := range keys {
		r.record(key, types.Condition{Key: string(key), Result: result, Reason: reason})
	}
}

// record merges condition into the rule's standing conclusion. The result
// higher in precedence wins, so the order in which a checker reaches its
// conclusions does not change what it reports.
func (r *report) record(key registry.FindingKey, condition types.Condition) {
	if key == "" {
		return
	}

	i, ok := r.index[key]
	if !ok {
		r.index[key] = len(r.result.Conditions)
		r.result.Conditions = append(r.result.Conditions, condition)
		return
	}

	standing := &r.result.Conditions[i]
	switch {
	case condition.Result.Outranks(standing.Result):
		*standing = condition
	case condition.Result == standing.Result:
		standing.Evidence = append(standing.Evidence, condition.Evidence...)
	}
}

// finish derives the check's result from its conditions and returns it.
func (r *report) finish() types.AuditResult {
	r.result.Conclude()
	return r.result
}

// evidence builds one evidence entry from a subject and alternating fact
// names and values. A fact with an empty value is omitted, so a caller can
// pass an observation that may not apply without branching.
func evidence(kind, subject string, nameValues ...string) types.Evidence {
	if len(nameValues)%factPair != 0 {
		panic("checker: evidence facts must be name and value pairs")
	}
	entry := types.Evidence{Kind: kind, Subject: subject}
	for ; len(nameValues) >= factPair; nameValues = nameValues[factPair:] {
		if name, value := nameValues[0], nameValues[1]; value != "" {
			entry.Facts = append(entry.Facts, types.Fact{Name: name, Value: value})
		}
	}
	return entry
}
