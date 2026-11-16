// internal/cvss/v4/score.go

// This file is a port of cvss_score.js, max_composed.js and max_severity.js from
// https://github.com/FIRSTdotorg/cvss-v4-calculator.
//
//	Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors
//	SPDX-License-Identifier: BSD-2-Clause
//
// The licence text is reproduced in internal/notices/THIRD_PARTY_NOTICES.md.
// The order of operations is the reference's, down to which maximal vector it
// picks and how a missing lower MacroVector is skipped, because a score that
// differs from FIRST's calculator by a tenth is a wrong score.

package v4

import (
	"fmt"
	"math"
	"strings"

	"github.com/papa0four/orkowatch/internal/cvss"
)

// step is the size of one level of a metric in a severity distance.
const step = 0.1

// levels gives each metric value its position on the metric's severity scale:
// 0 is the most severe. A severity distance is the difference of two positions.
var levels = map[string]map[string]float64{
	"AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
	"PR": {"N": 0.0, "L": 0.1, "H": 0.2},
	"UI": {"N": 0.0, "P": 0.1, "A": 0.2},
	"AC": {"L": 0.0, "H": 0.1},
	"AT": {"N": 0.0, "P": 0.1},
	"VC": {"H": 0.0, "L": 0.1, "N": 0.2},
	"VI": {"H": 0.0, "L": 0.1, "N": 0.2},
	"VA": {"H": 0.0, "L": 0.1, "N": 0.2},
	"SC": {"H": 0.1, "L": 0.2, "N": 0.3},
	"SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
	"SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
	"CR": {"H": 0.0, "M": 0.1, "L": 0.2},
	"IR": {"H": 0.0, "M": 0.1, "L": 0.2},
	"AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}

// maxComposed lists, for each level of each equivalence class, the highest
// severity vectors that belong to it, as the fragments of a vector string they
// are composed from (max_composed.js). EQ3 and EQ6 are listed together.
var (
	maxEQ1 = map[int][]string{
		0: {"AV:N/PR:N/UI:N/"},
		1: {"AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"},
		2: {"AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"},
	}
	maxEQ2 = map[int][]string{
		0: {"AC:L/AT:N/"},
		1: {"AC:H/AT:N/", "AC:L/AT:P/"},
	}
	maxEQ3EQ6 = map[int]map[int][]string{
		0: {
			0: {"VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"},
			1: {"VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"},
		},
		1: {
			0: {"VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"},
			1: {
				"VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
				"VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
				"VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
			},
		},
		2: {1: {"VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"}},
	}
	maxEQ4 = map[int][]string{
		0: {"SC:H/SI:S/SA:S/"},
		1: {"SC:H/SI:H/SA:H/"},
		2: {"SC:L/SI:L/SA:L/"},
	}
	maxEQ5 = map[int][]string{
		0: {"E:A/"},
		1: {"E:P/"},
		2: {"E:U/"},
	}
)

// maxSeverity is the depth of each level of each equivalence class, in steps:
// the largest severity distance a vector in the level can sit from its highest
// severity vector (max_severity.js).
var (
	maxSeverityEQ1    = map[int]float64{0: 1, 1: 4, 2: 5}
	maxSeverityEQ2    = map[int]float64{0: 1, 1: 2}
	maxSeverityEQ3EQ6 = map[int]map[int]float64{0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}}
	maxSeverityEQ4    = map[int]float64{0: 6, 1: 5, 2: 4}
)

// Score returns the vector's score from 0.0 to 10.0, to one decimal place. Not
// Defined Threat and Security Requirement metrics take the worst case, as the
// specification says, and a Modified Base metric replaces its Base metric.
func (v Vector) Score() float64 {
	return math.Floor(v.raw()*10+0.5) / 10
}

// raw is the score before it is rounded to one decimal place. It is separate so
// a test can tell a score that sits on a rounding tie, where two implementations
// that both follow the specification can differ by a tenth, from one that is wrong.
func (v Vector) raw() float64 {
	// No impact on the vulnerable or any subsequent system scores nothing.
	noImpact := true
	for _, name := range []string{"VC", "VI", "VA", "SC", "SI", "SA"} {
		if v.metric(name) != "N" {
			noImpact = false
		}
	}
	if noImpact {
		return 0.0
	}

	macro := v.macroVector()
	value := lookupScore(macro)

	eq := [6]int{}
	for i := range eq {
		eq[i] = int(macro[i] - '0')
	}

	// The score of the next lower MacroVector of each equivalence class, or NaN
	// where there is none.
	next := func(delta [6]int) float64 {
		var key strings.Builder
		for i, level := range eq {
			fmt.Fprintf(&key, "%d", level+delta[i])
		}
		return lookupScore(key.String())
	}
	lower1 := next([6]int{1, 0, 0, 0, 0, 0})
	lower2 := next([6]int{0, 1, 0, 0, 0, 0})
	lower36 := v.lowerEQ3EQ6(eq, next)
	lower4 := next([6]int{0, 0, 0, 1, 0, 0})
	lower5 := next([6]int{0, 0, 0, 0, 1, 0})

	d := v.severityDistance(eq)

	current1 := d["AV"] + d["PR"] + d["UI"]
	current2 := d["AC"] + d["AT"]
	current36 := d["VC"] + d["VI"] + d["VA"] + d["CR"] + d["IR"] + d["AR"]
	current4 := d["SC"] + d["SI"] + d["SA"]

	depth1 := maxSeverityEQ1[eq[0]] * step
	depth2 := maxSeverityEQ2[eq[1]] * step
	depth36 := maxSeverityEQ3EQ6[eq[2]][eq[5]] * step
	depth4 := maxSeverityEQ4[eq[3]] * step

	// The mean, over the equivalence classes that have a lower MacroVector, of the
	// share of the available score difference the vector sits below its highest
	// severity vector. EQ5 is always zero: the threat level has no depth.
	var sum float64
	var existing int
	for _, part := range []struct{ lower, current, depth float64 }{
		{lower1, current1, depth1},
		{lower2, current2, depth2},
		{lower36, current36, depth36},
		{lower4, current4, depth4},
	} {
		if available := value - part.lower; !math.IsNaN(available) {
			existing++
			sum += available * (part.current / part.depth)
		}
	}
	if !math.IsNaN(value - lower5) {
		existing++
	}

	var mean float64
	if existing > 0 {
		mean = sum / float64(existing)
	}
	value -= mean
	return math.Min(math.Max(value, 0), 10)
}

// lookupScore is the score FIRST's table gives a MacroVector, or NaN when no
// vector belongs to it.
func lookupScore(macro string) float64 {
	if score, ok := lookup[macro]; ok {
		return score
	}
	return math.NaN()
}

// lowerEQ3EQ6 is the score of the next lower MacroVector for the pair EQ3 and
// EQ6, which are not independent. From 00 two lower ones exist, and the higher
// of the two is taken; a comparison with a missing one is false, so a missing
// one on the left loses and a missing one on the right is what is taken.
func (v Vector) lowerEQ3EQ6(eq [6]int, next func([6]int) float64) float64 {
	switch {
	case eq[2] == 1 && eq[5] == 1, eq[2] == 0 && eq[5] == 1:
		return next([6]int{0, 0, 1, 0, 0, 0})
	case eq[2] == 1 && eq[5] == 0:
		return next([6]int{0, 0, 0, 0, 0, 1})
	case eq[2] == 0 && eq[5] == 0:
		left := next([6]int{0, 0, 0, 0, 0, 1})
		right := next([6]int{0, 0, 1, 0, 0, 0})
		if left > right {
			return left
		}
		return right
	default:
		return next([6]int{0, 0, 1, 0, 0, 1})
	}
}

// severityDistance is how far each metric of the vector sits below the highest
// severity vector it is measured against: the first of the composed highest
// severity vectors of its MacroVector that no metric of the vector exceeds. As in
// the reference, if none qualifies the last one tried is used.
func (v Vector) severityDistance(eq [6]int) map[string]float64 {
	var last map[string]float64
	for _, composed := range composeMaxVectors(eq) {
		max := parseFragments(composed)
		distance := make(map[string]float64, len(levels))
		negative := false
		for name, scale := range levels {
			distance[name] = scale[v.metric(name)] - scale[max[name]]
			if distance[name] < 0 {
				negative = true
			}
		}
		last = distance
		if !negative {
			return distance
		}
	}
	return last
}

// composeMaxVectors lists the highest severity vectors of a MacroVector in the
// order the reference tries them: every combination of the highest severity
// vectors of its equivalence classes, the first class varying slowest.
func composeMaxVectors(eq [6]int) []string {
	composed := []string{""}
	for _, group := range [][]string{maxEQ1[eq[0]], maxEQ2[eq[1]], maxEQ3EQ6[eq[2]][eq[5]], maxEQ4[eq[3]], maxEQ5[eq[4]]} {
		var next []string
		for _, head := range composed {
			for _, fragment := range group {
				next = append(next, head+fragment)
			}
		}
		composed = next
	}
	return composed
}

// parseFragments reads the metric:value fragments a highest severity vector is
// composed of.
func parseFragments(composed string) map[string]string {
	out := make(map[string]string)
	for _, part := range strings.Split(strings.TrimSuffix(composed, "/"), "/") {
		name, value, _ := strings.Cut(part, ":")
		out[name] = value
	}
	return out
}

// metric is the value a metric takes in scoring. Not Defined Exploit Maturity
// scores as Attacked, and Not Defined Security Requirements as High, the worst
// cases. A Modified Base metric that is defined replaces the Base metric.
func (v Vector) metric(name string) string {
	selected := v.values[name]
	switch name {
	case "E":
		if selected == "X" {
			return "A"
		}
	case "CR", "IR", "AR":
		if selected == "X" {
			return "H"
		}
	}
	if modified, ok := v.values["M"+name]; ok && modified != "X" {
		return modified
	}
	return selected
}

// macroVector is the six-digit key of the MacroVector the vector belongs to: the
// level, from 0 for the most severe, of each of the six equivalence classes.
func (v Vector) macroVector() string {
	av, pr, ui := v.metric("AV"), v.metric("PR"), v.metric("UI")
	var eq1 int
	switch {
	case av == "N" && pr == "N" && ui == "N":
		eq1 = 0
	case (av == "N" || pr == "N" || ui == "N") && av != "P":
		eq1 = 1
	default:
		eq1 = 2
	}

	eq2 := 1
	if v.metric("AC") == "L" && v.metric("AT") == "N" {
		eq2 = 0
	}

	vc, vi, va := v.metric("VC"), v.metric("VI"), v.metric("VA")
	var eq3 int
	switch {
	case vc == "H" && vi == "H":
		eq3 = 0
	case vc == "H" || vi == "H" || va == "H":
		eq3 = 1
	default:
		eq3 = 2
	}

	sc, si, sa := v.metric("SC"), v.metric("SI"), v.metric("SA")
	var eq4 int
	switch {
	case v.metric("MSI") == "S" || v.metric("MSA") == "S":
		eq4 = 0
	case sc == "H" || si == "H" || sa == "H":
		eq4 = 1
	default:
		eq4 = 2
	}

	var eq5 int
	switch v.metric("E") {
	case "A":
		eq5 = 0
	case "P":
		eq5 = 1
	default:
		eq5 = 2
	}

	eq6 := 1
	if (v.metric("CR") == "H" && vc == "H") || (v.metric("IR") == "H" && vi == "H") || (v.metric("AR") == "H" && va == "H") {
		eq6 = 0
	}

	return fmt.Sprintf("%d%d%d%d%d%d", eq1, eq2, eq3, eq4, eq5, eq6)
}

// Severity is the qualitative rating of a score, by the specification's Table 22,
// which is the same scale as CVSS v3.
func Severity(score float64) string {
	return cvss.Band(score)
}
