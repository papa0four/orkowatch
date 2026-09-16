// internal/security/checker/finding.go

package checker

import (
	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/security/types"
)

// emitFinding appends the types.Finding defined for key under osCtx to
// result.Findings. This is the single construction path for every
// types.Finding built from a registry definition; the struct literal appears
// nowhere else in the checker package. A key with no definition is a defect
// in the checker or the data file, not a host condition, so it panics rather
// than letting a detected condition report clean.
func emitFinding(result *types.AuditResult, osCtx registry.OSContext, key registry.FindingKey) {
	def, ok := registry.Lookup(osCtx, key)
	if !ok {
		panic("checker: no registry definition for finding key " + string(key) + " on platform " + string(osCtx.Platform))
	}
	result.Findings = append(result.Findings, types.Finding{
		Title:       def.Title,
		Severity:    def.Severity,
		Description: def.Description,
		Categories:  def.ToCategories(),
		Impact:      def.Impact,
		Resolution:  def.Resolution,
		References:  def.ToReferences(),
	})
}

// emitFindingOnce emits key at most once per seen. This is the single dedup
// idiom for once-per-Check findings in the checker package; callers do not
// declare their own bool flags or ad hoc seen maps.
func emitFindingOnce(result *types.AuditResult, osCtx registry.OSContext, key registry.FindingKey, seen map[registry.FindingKey]struct{}) {
	if _, dup := seen[key]; dup {
		return
	}
	emitFinding(result, osCtx, key)
	seen[key] = struct{}{}
}
