// internal/security/checker/sugate_test.go

package checker

import (
	"io/fs"
	"strings"
	"testing"
)

// The policies of the su and system services as FreeBSD 15.1 ships them.
const (
	suPolicyShipped = `#
#
# PAM configuration for the "su" service
#

# auth
auth		sufficient	pam_rootok.so		no_warn
auth		sufficient	pam_self.so		no_warn
auth		requisite	pam_group.so		no_warn group=wheel root_only fail_safe ruser
auth		include		system

# account
account		include		system

# session
session		required	pam_permit.so
`

	systemPolicyShipped = `#
# System-wide defaults
#

# auth
#auth		sufficient	pam_krb5.so		no_warn try_first_pass
auth		required	pam_unix.so		no_warn try_first_pass nullok

# account
account		required	pam_login_access.so
account		required	pam_unix.so
`
)

// pamPolicies serves the policies of a host by service name.
func pamPolicies(policies map[string]string) pamPolicy {
	return func(service string) ([]byte, error) {
		policy, ok := policies[service]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return []byte(policy), nil
	}
}

// The group su requires is the one the pam_group rule of its auth chain
// names, with included chains in place. Each form decided here is one su was
// seen to follow; any other is left undecided.
func TestReadSUGate(t *testing.T) {
	const (
		group  = "auth requisite pam_group.so no_warn group=wheel root_only fail_safe ruser\n"
		system = "auth include system\n"
	)
	replaced := func(old, new string) string { return strings.Replace(suPolicyShipped, old, new, 1) }

	cases := []struct {
		name      string
		su        string
		system    string
		want      suGate
		undecided string
	}{
		{name: "as shipped", su: suPolicyShipped, want: suGate{group: "wheel"}},
		{name: "another group", su: replaced("group=wheel", "group=sugroup"), want: suGate{group: "sugroup"}},
		{name: "no group named", su: "auth required pam_group.so no_warn\n" + system, want: suGate{group: "wheel"}},
		{name: "a module path", su: "auth requisite /usr/lib/pam_group.so group=staff\n", want: suGate{group: "staff"}},
		{name: "an optional facility", su: "-auth requisite pam_group.so group=staff\n", want: suGate{group: "staff"}},
		{name: "the rule in an included policy", su: system, system: group + systemPolicyShipped, want: suGate{group: "wheel"}},
		{name: "no rule", su: replaced("pam_group.so", "pam_permit.so"), want: suGate{open: true}},
		{name: "a rule of another facility", su: "account requisite pam_group.so group=wheel\n" + system, want: suGate{open: true}},
		{name: "the rule in a comment", su: "#" + group + system, want: suGate{open: true}},
		{name: "reversed", su: "auth requisite pam_group.so group=wheel deny\n",
			undecided: "line 1 of the policy of su gives pam_group the option deny"},
		{name: "by target", su: "auth requisite pam_group.so group=wheel luser\n",
			undecided: "line 1 of the policy of su gives pam_group the option luser"},
		{name: "a control that does not refuse", su: "auth sufficient pam_group.so group=wheel\n",
			undecided: "line 1 of the policy of su gives pam_group the control sufficient"},
		{name: "admitted ahead of the rule", su: "auth sufficient pam_permit.so\n" + group,
			undecided: "line 1 of the policy of su admits by pam_permit, and no pam_group rule is ahead of it"},
		{name: "admitted by an included policy", su: system, system: "auth sufficient pam_krb5.so\n",
			undecided: "line 1 of the policy of system admits by pam_krb5, and no pam_group rule is ahead of it"},
		{name: "two rules", su: group + "auth requisite pam_group.so group=staff\n",
			undecided: "line 2 of the policy of su is a second pam_group rule"},
		{name: "quoted", su: "auth requisite pam_group.so \"group=wheel\"\n",
			undecided: "the policy of su quotes or escapes part of a rule"},
		{name: "an included policy that is not there", su: "auth include local\n" + group,
			undecided: "the policy of local could not be read: file does not exist"},
		{name: "an included path", su: "auth include /etc/pam.d/system\n" + group,
			undecided: `the included policy "/etc/pam.d/system" is not the name of a service`},
		{name: "a policy that includes itself", su: "auth include su\n",
			undecided: "the policy of su is included from a policy it includes"},
		{name: "two policies that include each other", su: system, system: "auth include su\n",
			undecided: "the policy of su is included from a policy it includes"},
		{name: "a policy included twice", su: system + system + group, want: suGate{group: "wheel"}},
		{name: "a facility in another case", su: replaced("auth\t\trequisite", "Auth\t\trequisite"),
			undecided: `line 9 of the policy of su has the facility "Auth", which OpenPAM refuses, so su admits no one with this policy`},
		{name: "a facility OpenPAM does not have", su: suPolicyShipped + "bogus required pam_permit.so\n",
			undecided: `line 17 of the policy of su has the facility "bogus", which OpenPAM refuses, so su admits no one with this policy`},
		{name: "a control flag in another case", su: replaced("requisite", "Requisite"),
			undecided: `line 9 of the policy of su has the control flag "Requisite", which OpenPAM refuses, so su admits no one with this policy`},
		{name: "an include in another case", su: replaced("auth\t\tinclude", "auth\t\tInclude"),
			undecided: `line 10 of the policy of su has the control flag "Include", which OpenPAM refuses, so su admits no one with this policy`},
		{name: "a substack", su: replaced("auth\t\tinclude", "auth\t\tsubstack"),
			undecided: `line 10 of the policy of su has the control flag "substack", which OpenPAM refuses, so su admits no one with this policy`},
		{name: "a refused line in an included policy", su: suPolicyShipped, system: "Account required pam_unix.so\n",
			undecided: `line 1 of the policy of system has the facility "Account", which OpenPAM refuses, so su admits no one with this policy`},
	}

	for _, tc := range cases {
		if tc.system == "" {
			tc.system = systemPolicyShipped
		}
		got := readSUGate(pamPolicies(map[string]string{"su": tc.su, "system": tc.system}))
		tc.want.undecided = tc.undecided
		if got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}

	if got := readSUGate(pamPolicies(nil)); got.undecided != "the policy of su could not be read: file does not exist" {
		t.Errorf("no su policy: %+v", got)
	}
}
