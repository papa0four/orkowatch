// internal/cvss/v4/vector.go

// Package v4 scores CVSS v4.0 vectors by the algorithm FIRST publishes, as its
// reference calculator implements it (https://github.com/FIRSTdotorg/cvss-v4-calculator,
// Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors, BSD 2-Clause;
// the licence text is in internal/notices/THIRD_PARTY_NOTICES.md). Its consumers
// are the registry's baselines and the per-host environmental score (#165), and
// the v4.0 scores NVD publishes for a CVE (#90). A v4.0 score
// is not the value of an equation: it is the score of the MacroVector a vector
// belongs to, in FIRST's lookup table, less a distance the vector sits below
// the highest severity vector in that MacroVector. The port keeps the
// reference's order of operations, so a score is the one FIRST's calculator
// gives. It runs inside owatch: scoring needs no network access and sends
// nothing about a host anywhere.
package v4

import (
	"fmt"
	"slices"
	"strings"
)

// prefix begins every CVSS v4.0 vector string.
const prefix = "CVSS:4.0"

// Where each metric group ends in metrics. The first baseCount are Base metrics,
// which every vector must state; the rest are Threat, Environmental and
// Supplemental metrics, optional and Not Defined (X) when omitted.
const (
	baseCount          = 11
	threatCount        = baseCount + 1
	environmentalCount = threatCount + 14
)

// metricSpec is one metric of the specification: its abbreviation and the values
// it may take, in the order of the specification's Table 23.
type metricSpec struct {
	name   string
	values []string
}

// metrics lists every CVSS v4.0 metric in the order a vector string must state
// them, with the values the specification gives each (FIRST's metrics.js).
var metrics = []metricSpec{
	{"AV", []string{"N", "A", "L", "P"}},
	{"AC", []string{"L", "H"}},
	{"AT", []string{"N", "P"}},
	{"PR", []string{"N", "L", "H"}},
	{"UI", []string{"N", "P", "A"}},
	{"VC", []string{"H", "L", "N"}},
	{"VI", []string{"H", "L", "N"}},
	{"VA", []string{"H", "L", "N"}},
	{"SC", []string{"H", "L", "N"}},
	{"SI", []string{"H", "L", "N"}},
	{"SA", []string{"H", "L", "N"}},
	{"E", []string{"X", "A", "P", "U"}},
	{"CR", []string{"X", "H", "M", "L"}},
	{"IR", []string{"X", "H", "M", "L"}},
	{"AR", []string{"X", "H", "M", "L"}},
	{"MAV", []string{"X", "N", "A", "L", "P"}},
	{"MAC", []string{"X", "L", "H"}},
	{"MAT", []string{"X", "N", "P"}},
	{"MPR", []string{"X", "N", "L", "H"}},
	{"MUI", []string{"X", "N", "P", "A"}},
	{"MVC", []string{"X", "H", "L", "N"}},
	{"MVI", []string{"X", "H", "L", "N"}},
	{"MVA", []string{"X", "H", "L", "N"}},
	{"MSC", []string{"X", "H", "L", "N"}},
	{"MSI", []string{"X", "S", "H", "L", "N"}},
	{"MSA", []string{"X", "S", "H", "L", "N"}},
	{"S", []string{"X", "N", "P"}},
	{"AU", []string{"X", "N", "Y"}},
	{"R", []string{"X", "A", "U", "I"}},
	{"V", []string{"X", "D", "C"}},
	{"RE", []string{"X", "L", "M", "H"}},
	{"U", []string{"X", "Clear", "Green", "Amber", "Red"}},
}

// Vector is a parsed CVSS v4.0 vector. Every metric of the specification has a
// value in it: the one the string gave, or Not Defined for one it omitted.
type Vector struct {
	text   string
	values map[string]string
}

// Parse reads a CVSS v4.0 vector string. It applies the specification's rules for
// one: the label CVSS:4.0, every Base metric, the metrics in the order of its
// Table 23 and no other, no metric twice, and a value from the metric's own set,
// case sensitive. An omitted Threat, Environmental or Supplemental metric is Not
// Defined. A vector that breaks a rule is refused with the metric that breaks it.
func Parse(vector string) (Vector, error) {
	parts := strings.Split(vector, "/")
	if parts[0] != prefix {
		return Vector{}, fmt.Errorf("%q is not a CVSS v4.0 vector: it does not begin with %s", vector, prefix)
	}

	values := make(map[string]string, len(metrics))
	next := 0
	for _, part := range parts[1:] {
		name, value, ok := strings.Cut(part, ":")
		if !ok || strings.Contains(value, ":") {
			return Vector{}, fmt.Errorf("%q has %q where a metric:value pair belongs", vector, part)
		}
		at := slices.IndexFunc(metrics[next:], func(m metricSpec) bool { return m.name == name })
		if at < 0 {
			return Vector{}, fmt.Errorf("%q has metric %q that is unknown, repeated or out of the specified order", vector, name)
		}
		if at > 0 && next < baseCount {
			return Vector{}, fmt.Errorf("%q is missing the Base metric %s before %s", vector, metrics[next].name, name)
		}
		spec := metrics[next+at]
		if !slices.Contains(spec.values, value) {
			return Vector{}, fmt.Errorf("%q gives metric %s the value %q, which is not one of %s", vector, name, value, strings.Join(spec.values, ", "))
		}
		values[name] = value
		next += at + 1
	}

	for _, spec := range metrics[:baseCount] {
		if _, ok := values[spec.name]; !ok {
			return Vector{}, fmt.Errorf("%q is missing the Base metric %s", vector, spec.name)
		}
	}
	for _, spec := range metrics[baseCount:] {
		if _, ok := values[spec.name]; !ok {
			values[spec.name] = "X"
		}
	}
	return Vector{text: vector, values: values}, nil
}

// CalculatorURL is the address that opens FIRST's CVSS v4.0 calculator on a vector:
// the calculator reads the vector from the fragment of the address. It is a link
// for a reader to check a score with, and owatch never requests it.
func CalculatorURL(vector string) string {
	return "https://www.first.org/cvss/calculator/4.0#" + vector
}

// String returns the vector as it was given.
func (v Vector) String() string { return v.text }

// Nomenclature is the label FIRST requires on a displayed score so that it says
// which metrics it was made from: CVSS-B for Base metrics, CVSS-BT with a Threat
// metric, CVSS-BE with an Environmental one and CVSS-BTE with both.
func (v Vector) Nomenclature() string {
	label := "CVSS-B"
	if v.values["E"] != "X" {
		label += "T"
	}
	for _, spec := range metrics[threatCount:environmentalCount] {
		if v.values[spec.name] != "X" {
			return label + "E"
		}
	}
	return label
}
