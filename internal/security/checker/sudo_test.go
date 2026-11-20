// internal/security/checker/sudo_test.go

package checker

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// What sudo -l -U prints in the C locale, in the form observed on the
// releases named, with the long values of the Defaults line shortened.
const (
	// sudo 1.9.9, Ubuntu 22.04: a group entry and one by name.
	sudoListAdmitted = `Matching Defaults entries for u_group on 91be51551d2d:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User u_group may run the following commands on 91be51551d2d:
    (ALL : ALL) ALL
    (ALL) ALL
`
	// sudo 1.9.17p2, AlmaLinux 9.
	sudoListNotAllowed = `User u_none is not allowed to run sudo on b985ff8c10f9.
`
	sudoListTagged = `Matching Defaults entries for u_b on 38e1bd656ea9:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User u_b may run the following commands on 38e1bd656ea9:
    (ALL) ALL
    (root) NOPASSWD: /usr/bin/id, PASSWD: /usr/bin/whoami
`
	// sudo 1.9.9, Ubuntu 22.04: authenticate turned off for the account.
	sudoListUnauthenticated = `Matching Defaults entries for u_c on 12decebd2202:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, !authenticate

User u_c may run the following commands on 12decebd2202:
    (ALL) ALL
    (root) PASSWD: /usr/bin/whoami
`
	// sudo 1.9.15p5, openSUSE Leap 15.6, as packaged.
	sudoListTargetpw = `Matching Defaults entries for u_none on fa91af1a99fe:
    always_set_home, env_reset, env_keep="LANG LC_ADDRESS LC_CTYPE LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE LC_TIME LC_ALL LANGUAGE LINGUAS XDG_SESSION_COOKIE", !insults, secure_path=/usr/sbin\:/usr/bin\:/sbin\:/bin, targetpw

User u_none may run the following commands on fa91af1a99fe:
    (ALL) ALL
`
	// sudo 1.9.17p2, openSUSE Tumbleweed: a second block of defaults, and
	// rootpw set for the account beside the packaged targetpw.
	sudoListCommandDefaults = `Matching Defaults entries for u_name on 7d1c0a2b9e44:
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, always_set_home, env_reset, !insults, targetpw, rootpw

Runas and Command-specific defaults for u_name:
    Defaults!/usr/sbin/visudo env_keep+="SUDO_EDITOR EDITOR VISUAL"

User u_name may run the following commands on 7d1c0a2b9e44:
    (ALL) ALL
`
	sudoSyntaxError = `/etc/sudoers.d/20-broken:1:14: syntax error
u_a ALL=(ALL ALL
             ^~~
`
)

func TestParseSudoList(t *testing.T) {
	cases := []struct {
		name       string
		listing    string
		entries    []string
		unprompted []string
		borrowed   string
	}{
		{"admitted", sudoListAdmitted, []string{"(ALL : ALL) ALL", "(ALL) ALL"}, nil, ""},
		{"not allowed", sudoListNotAllowed, nil, nil, ""},
		{"the NOPASSWD tag", sudoListTagged,
			[]string{"(ALL) ALL", "(root) NOPASSWD: /usr/bin/id, PASSWD: /usr/bin/whoami"},
			[]string{"(root) NOPASSWD: /usr/bin/id, PASSWD: /usr/bin/whoami"}, ""},
		{"authenticate off, and an entry that turns it back on", sudoListUnauthenticated,
			[]string{"(ALL) ALL", "(root) PASSWD: /usr/bin/whoami"}, []string{"(ALL) ALL"}, ""},
		{"targetpw", sudoListTargetpw, []string{"(ALL) ALL"}, nil, "targetpw"},
		{"command defaults are not entries, and two settings", sudoListCommandDefaults, []string{"(ALL) ALL"}, nil, "targetpw, rootpw"},
		{"carriage returns", strings.ReplaceAll(sudoListTagged, "\n", "\r\n"),
			[]string{"(ALL) ALL", "(root) NOPASSWD: /usr/bin/id, PASSWD: /usr/bin/whoami"},
			[]string{"(root) NOPASSWD: /usr/bin/id, PASSWD: /usr/bin/whoami"}, ""},
		{"nothing printed", "", nil, nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseSudoList([]byte(tc.listing))
			if !slices.Equal(got.entries, tc.entries) {
				t.Errorf("entries = %q, want %q", got.entries, tc.entries)
			}
			if !slices.Equal(got.unprompted, tc.unprompted) {
				t.Errorf("unprompted = %q, want %q", got.unprompted, tc.unprompted)
			}
			if got.borrowed != tc.borrowed {
				t.Errorf("borrowed = %q, want %q", got.borrowed, tc.borrowed)
			}
			if got.shell {
				t.Error("shell is set by the list, which does not say which rule is in force")
			}
		})
	}
}

// sudoReply is what a scripted sudo answers to one request.
type sudoReply struct {
	stdout, stderr string
	status         int
	err            error
}

// scriptedSudo answers each request from replies, keyed by its arguments, and
// records the requests made.
func scriptedSudo(replies map[string]sudoReply, asked *[]string) sudoRun {
	return func(_ context.Context, args ...string) ([]byte, []byte, int, error) {
		request := strings.Join(args, " ")
		*asked = append(*asked, request)
		reply, ok := replies[request]
		if !ok {
			return nil, nil, 0, errors.New("unscripted request: " + request)
		}
		return []byte(reply.stdout), []byte(reply.stderr), reply.status, reply.err
	}
}

func TestAskSudo(t *testing.T) {
	var asked []string
	run := scriptedSudo(map[string]sudoReply{
		"-l -U u_group":         {stdout: sudoListAdmitted},
		"-l -U u_group /bin/sh": {stdout: "/bin/sh\n"},
		"-l -U u_none":          {stdout: sudoListNotAllowed},
		// Both rules are listed; the later one undoes the earlier.
		"-l -U u_last":         {stdout: sudoListAdmitted},
		"-l -U u_last /bin/sh": {status: sudoDenied},
		"-l -U u_b":            {stdout: sudoListTagged},
		"-l -U u_b /bin/sh":    {stdout: "/bin/sh\n"},
	}, &asked)

	view, err := askSudo(context.Background(), run, []string{"u_group", "u_none", "u_last", "u_b"})
	if err != nil {
		t.Fatalf("askSudo: %v", err)
	}
	if len(view.complaints) != 0 {
		t.Errorf("complaints = %q, want none", view.complaints)
	}

	shells := map[string]bool{"u_group": true, "u_none": false, "u_last": false, "u_b": true}
	for account, want := range shells {
		if got := view.answers[account].shell; got != want {
			t.Errorf("%s: shell = %v, want %v", account, got, want)
		}
	}
	if got := view.answers["u_last"].entries; len(got) == 0 {
		t.Error("u_last: the entries sudo listed are dropped")
	}
	if got := view.answers["u_b"].unprompted; len(got) != 1 {
		t.Errorf("u_b: unprompted = %q, want the tagged entry", got)
	}
	// An account sudo does not admit is not asked about a command.
	if slices.Contains(asked, "-l -U u_none /bin/sh") {
		t.Error("sudo was asked about a shell for an account it lists nothing for")
	}
}

// sudo answers from the rules it could read and says on standard error which
// it could not: the answers stand and the complaint is kept once.
func TestAskSudoComplaints(t *testing.T) {
	var asked []string
	run := scriptedSudo(map[string]sudoReply{
		"-l -U u_a":         {stdout: sudoListAdmitted, stderr: sudoSyntaxError},
		"-l -U u_a /bin/sh": {stdout: "/bin/sh\n", stderr: sudoSyntaxError},
		"-l -U u_b":         {stdout: sudoListNotAllowed, stderr: "sudo: /etc/sudoers.d/30-mode is world writable\n"},
	}, &asked)

	view, err := askSudo(context.Background(), run, []string{"u_a", "u_b"})
	if err != nil {
		t.Fatalf("askSudo: %v", err)
	}
	want := []string{"/etc/sudoers.d/20-broken:1:14: syntax error", "sudo: /etc/sudoers.d/30-mode is world writable"}
	if !slices.Equal(view.complaints, want) {
		t.Errorf("complaints = %q, want %q", view.complaints, want)
	}
	if !view.answers["u_a"].shell {
		t.Error("u_a: the answer sudo gave beside its complaint is dropped")
	}
}

func TestAskSudoFailures(t *testing.T) {
	cases := []struct {
		name    string
		replies map[string]sudoReply
		want    string
	}{
		{"an account sudo does not know",
			map[string]sudoReply{"-l -U ghost": {stderr: "sudo: unknown user ghost\n", status: 1}},
			"sudo -l -U ghost: exit status 1: sudo: unknown user ghost"},
		{"sudo cannot be run",
			map[string]sudoReply{"-l -U ghost": {err: errors.New("exec: no such file")}},
			"sudo could not be run: exec: no such file"},
		{"the command question ends in neither answer",
			map[string]sudoReply{
				"-l -U ghost":         {stdout: sudoListAdmitted},
				"-l -U ghost /bin/sh": {stderr: "sudo: a terminal is required\n", status: 2},
			},
			"sudo -l -U ghost /bin/sh: exit status 2: sudo: a terminal is required"},
		{"the command question cannot be run",
			map[string]sudoReply{
				"-l -U ghost":         {stdout: sudoListAdmitted},
				"-l -U ghost /bin/sh": {err: errors.New("signal: killed")},
			},
			"sudo could not be run: signal: killed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var asked []string
			_, err := askSudo(context.Background(), scriptedSudo(tc.replies, &asked), []string{"ghost"})
			if err == nil || err.Error() != tc.want {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
