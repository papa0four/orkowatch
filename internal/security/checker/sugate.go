// internal/security/checker/sugate.go

// Who su admits to root where PAM decides it: the pam_group rule in the auth
// chain of the su service. pam_group(8): "accepts or rejects users based on
// their membership in a particular file group". The forms decided are the
// ones su was seen to follow on FreeBSD 15.1; any other is left undecided
// with the reason.

package checker

import (
	"fmt"
	"path"
	"slices"
	"strings"
)

const (
	// suService is the service whose policy su follows.
	suService = "su"

	// suGroupModule is the module that decides by group, and suGroupDefault
	// the group it checks when given none. pam_group(8): "The default is
	// wheel".
	suGroupModule  = "pam_group"
	suGroupDefault = "wheel"

	// suGroupOption names the group, suGroupDeny reverses the test and
	// suGroupTarget tests the target account in place of the applicant.
	suGroupOption = "group="
	suGroupDeny   = "deny"
	suGroupTarget = "luser"

	pamModuleSuffix   = ".so"
	pamOptionalPrefix = "-"
	pamInclude        = "include"
	pamAuth           = "auth"
	pamQuoting        = "\"'\\"
)

var (
	// openPAMFacilities and openPAMControls are the facilities and control
	// flags pam.conf(5) lists. OpenPAM reads both as written: with any
	// other on a line, in whatever facility, su on FreeBSD 15.1 logged
	// "invalid facility" or "invalid control flag" and ended in "pam_start:
	// System error" for every applicant, a member of wheel included.
	openPAMFacilities = []string{pamAuth, "account", "session", "password"}
	openPAMControls   = []string{"required", "requisite", "sufficient", "binding", "optional", pamInclude}

	// suGroupControls are the controls under which a rejection by pam_group
	// refuses the applicant.
	suGroupControls = []string{"requisite", "required"}

	// suAdmitsBefore are the controls under which a rule ahead of pam_group
	// admits an applicant without reaching it, and suAdmitsSelf the modules
	// that under them admit only root or an applicant who is the target.
	suAdmitsBefore = []string{"sufficient", "binding"}
	suAdmitsSelf   = []string{"pam_rootok", "pam_self"}
)

type (
	// suGate is what the su service requires of an applicant for root: group
	// is the group pam_group checks, open is set where no rule checks one,
	// and undecided says why the chain was not decided.
	suGate struct {
		group     string
		open      bool
		undecided string
	}

	// pamPolicy returns the policy file of a service.
	pamPolicy func(service string) ([]byte, error)

	// suAuthRule is one rule of the auth chain, with the service whose policy
	// holds it.
	suAuthRule struct {
		pamRule
		service string
	}
)

// readSUGate decides the auth chain of the su service, with the chains it
// includes in place. pam.conf(5): "The include form of entry causes entries
// from a different chain (specified by other-system-name) to be included in
// the current one."
func readSUGate(read pamPolicy) suGate {
	var reading includeChain
	chain, undecided := suAuthChain(suService, read, &reading)
	if undecided != "" {
		return suGate{undecided: undecided}
	}

	var gate *suGate
	for _, rule := range chain {
		module := strings.TrimSuffix(path.Base(rule.target), pamModuleSuffix)

		switch {
		case module == suGroupModule && gate != nil:
			return suGate{undecided: rule.at() + " is a second " + suGroupModule + " rule"}
		case module == suGroupModule:
			decided := suGroupRule(rule)
			if decided.undecided != "" {
				return decided
			}
			gate = &decided
		case gate != nil:
			// A rule after the group is checked admits no one the group
			// rule refused.
		case slices.Contains(suAdmitsBefore, rule.control) && !slices.Contains(suAdmitsSelf, module):
			return suGate{undecided: fmt.Sprintf("%s admits by %s, and no %s rule is ahead of it", rule.at(), module, suGroupModule)}
		}
	}

	if gate == nil {
		return suGate{open: true}
	}
	return *gate
}

// suAuthChain returns the auth rules of a service in the order PAM runs
// them, or why they could not be put in order. OpenPAM splits a rule by the
// shell's quoting rules (pam.conf(5)), which the rule parser here does not
// follow, so a policy that quotes or escapes anything is left undecided. A
// line OpenPAM refuses is not passed over: su was seen to admit no one with
// a policy holding one, so the policy is left undecided with the line. An
// include names a service and never a path ("invalid service name"), and
// pam.conf(5) warns that "there is currently no loop detection in place", so
// a policy that leads back to itself is left undecided as well.
func suAuthChain(service string, read pamPolicy, reading *includeChain) ([]suAuthRule, string) {
	if service == "" || strings.ContainsAny(service, `/\`) {
		return nil, fmt.Sprintf("the included policy %q is not the name of a service", service)
	}
	leave, ok := reading.enter(service)
	if !ok {
		return nil, fmt.Sprintf("the policy of %s is included from a policy it includes", service)
	}
	defer leave()

	data, err := read(service)
	if err != nil {
		return nil, fmt.Sprintf("the policy of %s could not be read: %v", service, err)
	}
	if strings.ContainsAny(stripPAMComments(data), pamQuoting) {
		return nil, fmt.Sprintf("the policy of %s quotes or escapes part of a rule", service)
	}
	rules, err := parsePAMRules(data, false)
	if err != nil {
		return nil, fmt.Sprintf("the policy of %s: %v", service, err)
	}

	var chain []suAuthRule
	for _, rule := range rules {
		entry := suAuthRule{pamRule: rule, service: service}
		facility := strings.TrimPrefix(rule.typ, pamOptionalPrefix)
		switch {
		case !slices.Contains(openPAMFacilities, facility):
			return nil, fmt.Sprintf("%s has the facility %q, which OpenPAM refuses, so su admits no one with this policy", entry.at(), rule.typ)
		case !slices.Contains(openPAMControls, rule.control):
			return nil, fmt.Sprintf("%s has the control flag %q, which OpenPAM refuses, so su admits no one with this policy", entry.at(), rule.control)
		case facility != pamAuth:
		case rule.control != pamInclude:
			chain = append(chain, entry)
		default:
			included, undecided := suAuthChain(rule.target, read, reading)
			if undecided != "" {
				return nil, undecided
			}
			chain = append(chain, included...)
		}
	}
	return chain, ""
}

// at names where the rule is.
func (r suAuthRule) at() string {
	return fmt.Sprintf("line %d of the policy of %s", r.line, r.service)
}

// suGroupRule decides one pam_group rule.
func suGroupRule(rule suAuthRule) suGate {
	if !slices.Contains(suGroupControls, rule.control) {
		return suGate{undecided: fmt.Sprintf("%s gives %s the control %s", rule.at(), suGroupModule, rule.control)}
	}

	gate := suGate{group: suGroupDefault}
	for _, arg := range rule.args {
		switch name, found := strings.CutPrefix(arg, suGroupOption); {
		case found:
			gate.group = name
		case arg == suGroupDeny, arg == suGroupTarget:
			return suGate{undecided: fmt.Sprintf("%s gives %s the option %s", rule.at(), suGroupModule, arg)}
		}
	}
	return gate
}

// stripPAMComments returns data without the text from a # to the end of its
// line, which is where a quoting character means nothing.
func stripPAMComments(data []byte) string {
	var kept strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		if comment := strings.IndexByte(line, '#'); comment >= 0 {
			line = line[:comment]
		}
		kept.WriteString(line)
		kept.WriteByte('\n')
	}
	return kept.String()
}
