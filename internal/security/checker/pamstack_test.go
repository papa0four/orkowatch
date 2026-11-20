// internal/security/checker/pamstack_test.go

package checker

import (
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

// A rule is read as libpam assembles and splits it: comments, joined lines,
// bracketed tokens and the line it starts on.
func TestParsePAMRules(t *testing.T) {
	data := "# header\n" +
		"\n" +
		"auth  [success=2 default=ignore]  pam_sss.so use_first_pass # trailing\n" +
		"  account required \\\n" +
		"\n" +
		"   pam_unix.so\n" +
		"password requisite pam_pwq.so [a=\\]b c]\n" +
		"session optional pam_x.so # ends here \\\n" +
		"session optional pam_y.so\n"
	rules, err := parsePAMRules([]byte(data), false)
	if err != nil {
		t.Fatal(err)
	}
	want := []pamRule{
		{line: 3, typ: "auth", control: "success=2 default=ignore", target: "pam_sss.so", args: []string{"use_first_pass"}},
		{line: 4, typ: "account", control: "required", target: "pam_unix.so"},
		{line: 7, typ: "password", control: "requisite", target: "pam_pwq.so", args: []string{"a=]b c"}},
		{line: 8, typ: "session", control: "optional", target: "pam_x.so"},
		{line: 9, typ: "session", control: "optional", target: "pam_y.so"},
	}
	if !reflect.DeepEqual(rules, want) {
		t.Errorf("got %+v\nwant %+v", rules, want)
	}
	if got := pamTokens(`a [b\]c d] e`); !reflect.DeepEqual(got, []string{"a", "b]c d", "e"}) {
		t.Errorf("tokens %q", got)
	}

	rules, err = parsePAMRules([]byte("login auth required pam_unix.so\nauth required \\\n"), true)
	if err == nil || !strings.Contains(err.Error(), "line 2 is continued") || len(rules) != 1 || rules[0].service != "login" {
		t.Errorf("a file ending inside a joined line: %+v, %v", rules, err)
	}
}

// The stack is followed through include, substack and, on the Debian family,
// @include; each service comes from the first directory holding it; a rule is
// recorded once with every service that reaches it.
func TestReadPAMStack(t *testing.T) {
	modules := []string{"pam_sss.so", "pam_krb5.so"}
	debian := pamLayout{dirs: []string{"etc/pam.d", "usr/lib/pam.d"}, conf: "etc/pam.conf", atInclude: true}
	fsys := fstest.MapFS{
		"etc/pam.d/login":       {Data: []byte("@include common-auth\nsession include common-session\n")},
		"etc/pam.d/su":          {Data: []byte("auth substack common-auth\naccount include common-auth\n")},
		"etc/pam.d/common-auth": {Data: []byte("auth [success=1 default=ignore] pam_sss.so\naccount required pam_krb5.so\n")},
		"etc/pam.d/loop":        {Data: []byte("auth include loop\n")},
		"etc/pam.d/broken":      {Data: []byte("auth include missing\n")},
		"usr/lib/pam.d/login":   {Data: []byte("auth required pam_krb5.so\n")},
		"usr/lib/pam.d/vendor":  {Data: []byte("-session optional /usr/lib/security/pam_sss.so\n@include common-auth\n")},
	}
	stack := readPAMStack(fsys, debian, modules)
	got := map[string]string{}
	for _, module := range modules {
		for _, w := range stack.wiring(module) {
			got[w.subject+" "+w.line] = w.services
		}
	}
	want := map[string]string{
		"auth pam_sss.so /etc/pam.d/common-auth:1":     "common-auth, login, su, vendor",
		"account pam_krb5.so /etc/pam.d/common-auth:2": "common-auth, login, su, vendor",
		"session pam_sss.so /usr/lib/pam.d/vendor:1":   "vendor",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("wiring %v\nwant %v", got, want)
	}
	problems := strings.Join(stack.problems, "\n")
	for _, p := range []string{
		"/etc/pam.d/loop is included from a file it includes",
		"/etc/pam.d/broken includes missing, which is not present",
		"/etc/pam.d/login includes common-session, which is not present",
	} {
		if !strings.Contains(problems, p) {
			t.Errorf("problems %q lack %q", problems, p)
		}
	}

	// Outside the Debian family @include is a type libpam does not know, and
	// a relative include is looked for in every service directory.
	other := debian
	other.atInclude = false
	fsys = fstest.MapFS{
		"etc/pam.d/login":           {Data: []byte("@include common-auth\nauth include system-auth\n")},
		"usr/lib/pam.d/system-auth": {Data: []byte("auth sufficient pam_sss.so\n")},
		"etc/pam.d/common-auth":     {Data: []byte("auth required pam_krb5.so\n")},
	}
	stack = readPAMStack(fsys, other, modules)
	if w := stack.wiring("pam_krb5.so"); len(w) != 1 || w[0].services != "common-auth" {
		t.Errorf("@include was followed outside the Debian family: %+v", w)
	}
	if w := stack.wiring("pam_sss.so"); len(w) != 1 || w[0].line != "/usr/lib/pam.d/system-auth:1" || w[0].services != "login, system-auth" {
		t.Errorf("a relative include in the vendor directory: %+v", w)
	}

	// pam.conf is read only when no service directory exists.
	fsys = fstest.MapFS{"etc/pam.conf": {Data: []byte("sshd auth required pam_sss.so\nother account required pam_krb5.so\n")}}
	stack = readPAMStack(fsys, other, modules)
	if w := stack.wiring("pam_sss.so"); len(w) != 1 || w[0].line != "/etc/pam.conf:1" || w[0].services != "sshd" {
		t.Errorf("pam.conf: %+v", w)
	}
	fsys["usr/lib/pam.d/login"] = &fstest.MapFile{Data: []byte("auth required pam_unix.so\n")}
	if w := readPAMStack(fsys, other, modules).wiring("pam_sss.so"); len(w) != 0 {
		t.Errorf("pam.conf was read beside a service directory: %+v", w)
	}
}
