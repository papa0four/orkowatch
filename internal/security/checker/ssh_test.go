// internal/security/checker/ssh_test.go

package checker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/papa0four/orkowatch/internal/security/finding"
	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/sockets"
)

// writeConfig writes files, keyed by name, into a new directory and returns it.
func writeConfig(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// parseIn parses sshd_config in dir, resolving includes against dir.
func parseIn(t *testing.T, dir string) (sshConfig, error) {
	t.Helper()
	path := filepath.Join(dir, "sshd_config")
	file, err := os.Open(path) // #nosec G304 -- a file the test wrote
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close() //nolint:errcheck // read-only test file
	return parseSSHDConfig(context.Background(), file, path, dir)
}

// The global value the parser takes is the one sshd uses. Each expectation is
// what sshd -T printed for the same file (OpenSSH 10.2p1 on Ubuntu, and
// OpenSSH for Windows 9.5p2 for keyword and value case).
func TestParseMatchesSSHD(t *testing.T) {
	cases := map[string]struct {
		config, keyword, want string
	}{
		"the first value wins":           {"PermitRootLogin no\nPermitRootLogin yes\n", keywordRootLogin, "no"},
		"a keyword in lower case":        {"permitrootlogin yes\n", keywordRootLogin, "yes"},
		"a keyword in upper case":        {"PERMITROOTLOGIN Yes\n", keywordRootLogin, "Yes"},
		"a quoted value":                 {"PermitRootLogin \"no\"\n", keywordRootLogin, "no"},
		"an equals sign":                 {"PermitRootLogin=yes\n", keywordRootLogin, "yes"},
		"an equals sign with spaces":     {"PermitRootLogin = yes\n", keywordRootLogin, "yes"},
		"tabs around an equals sign":     {"PermitRootLogin\t=\tyes\n", keywordRootLogin, "yes"},
		"a trailing comment":             {"PermitRootLogin no # comment\n", keywordRootLogin, "no"},
		"leading white space":            {"   PermitRootLogin yes\n", keywordRootLogin, "yes"},
		"an indented comment":            {"  # PermitRootLogin yes\nPermitRootLogin no\n", keywordRootLogin, "no"},
		"CRLF line endings":              {"PasswordAuthentication no\r\n", keywordPasswordAuth, "no"},
		"a value in another case":        {"PasswordAuthentication No\n", keywordPasswordAuth, "No"},
		"a Match value is not global":    {"PermitRootLogin no\nMatch User alice\n  PermitRootLogin yes\n", keywordRootLogin, "no"},
		"global lines before Match only": {"Match User alice\nPermitRootLogin yes\n", keywordRootLogin, ""},
	}
	for name, c := range cases {
		dir := writeConfig(t, map[string]string{"sshd_config": c.config})
		config, err := parseIn(t, dir)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got := strings.TrimSuffix(config.global[c.keyword].value, "\r"); got != c.want {
			t.Errorf("%s: %s = %q, want %q", name, c.keyword, got, c.want)
		}
	}
}

// A value sshd refuses is recorded as refused, with what sshd -T objected to,
// and is not taken for a value.
func TestParseRecordsWhatSSHDRefuses(t *testing.T) {
	for config, want := range map[string]string{
		"PermitRootLogin maybe\n":                          "not one sshd accepts",
		"PasswordAuthentication\n":                         "no value",
		"PermitRootLogin \"forced-commands-only\" extra\n": "more than one value",
	} {
		dir := writeConfig(t, map[string]string{"sshd_config": config})
		parsed, err := parseIn(t, dir)
		if err != nil {
			t.Errorf("%q: %v", config, err)
			continue
		}
		var setting sshSetting
		for _, s := range parsed.global {
			setting = s
		}
		if !setting.found || !strings.Contains(setting.rejected, want) {
			t.Errorf("%q: setting %+v, want one refused for %q", config, setting, want)
		}
	}
	for _, config := range []string{"PermitRootLogin \"\"\n", "PermitRootLogin \"no\n", "Match\n"} {
		dir := writeConfig(t, map[string]string{"sshd_config": config})
		if _, err := parseIn(t, dir); err == nil {
			t.Errorf("%q: sshd refuses this line and the parser accepted it", config)
		}
	}
}

// Included files are read in place, a glob in lexical order, so the first value
// may come from an included file; an Include that matches nothing is skipped;
// a relative Include is resolved against the configuration's directory.
func TestParseFollowsInclude(t *testing.T) {
	dir := writeConfig(t, map[string]string{
		"sshd_config":         "Include conf.d/*.conf\nInclude conf.d/none-*.conf\nInclude missing.conf\nPermitRootLogin no\n",
		"conf.d/20-b.conf":    "PermitRootLogin yes\n",
		"conf.d/10-a.conf":    "PermitRootLogin forced-commands-only\nPasswordAuthentication no\n",
		"conf.d/30-c.conf.no": "PasswordAuthentication yes\n",
	})
	config, err := parseIn(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := config.global[keywordRootLogin].value; got != "forced-commands-only" {
		t.Errorf("PermitRootLogin = %q, want the lexically first included value", got)
	}
	if got := config.global[keywordPasswordAuth].value; got != "no" {
		t.Errorf("PasswordAuthentication = %q, want no", got)
	}

	absolute := writeConfig(t, map[string]string{"x.conf": "PermitRootLogin yes\n"})
	dir = writeConfig(t, map[string]string{
		"sshd_config": "Include " + filepath.ToSlash(strings.TrimPrefix(absolute, filepath.VolumeName(absolute))) + "/x.conf\n",
	})
	config, err = parseIn(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := config.global[keywordRootLogin].value; got != "yes" {
		t.Errorf("an Include beginning with a slash was not read: PermitRootLogin = %q", got)
	}
}

// A Match block holds what is set under it, an Include inside it, and a Match
// begun in an included file ends with that file. Only the first value in a
// block is kept.
func TestParseScopesMatchBlocks(t *testing.T) {
	dir := writeConfig(t, map[string]string{
		"sshd_config": "Include m.conf\nPermitRootLogin no\nMatch User bob\nInclude inner.conf\nPermitRootLogin forced-commands-only\nMatch Address 10.0.0.0/8\nPasswordAuthentication yes\n",
		"m.conf":      "Match Group admins\n PasswordAuthentication no\n",
		"inner.conf":  "PermitRootLogin yes\n",
	})
	config, err := parseIn(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := config.global[keywordRootLogin].value; got != "no" {
		t.Errorf("global PermitRootLogin = %q: a Match in an included file did not end with it", got)
	}
	want := []struct{ criteria, keyword, value string }{
		{"Group admins", keywordPasswordAuth, "no"},
		{"User bob", keywordRootLogin, "yes"},
		{"Address 10.0.0.0/8", keywordPasswordAuth, "yes"},
	}
	if len(config.blocks) != len(want) {
		t.Fatalf("blocks = %+v", config.blocks)
	}
	for i, w := range want {
		block := config.blocks[i]
		if block.criteria != w.criteria || block.settings[w.keyword].value != w.value {
			t.Errorf("block %d = %+v, want %s with %s %s", i, block, w.criteria, w.keyword, w.value)
		}
	}
}

// An Include that leads back to a file being read is refused, as sshd refuses
// it, rather than followed without end.
func TestParseRefusesIncludeLoop(t *testing.T) {
	dir := writeConfig(t, map[string]string{
		"sshd_config": "Include a.conf\n",
		"a.conf":      "Include b.conf\n",
		"b.conf":      "Include sshd_config\n",
	})
	if _, err := parseIn(t, dir); err == nil || !strings.Contains(err.Error(), "leads back") {
		t.Errorf("error %v, want a refused loop", err)
	}
}

// The rules follow the configuration sshd assembles: an unsafe value in a
// Match block fails the rule with its criteria, a value sshd refuses is not
// judged, and a value in any case is judged as sshd reads it.
func TestCheckSSHDConfigJudgesTheAssembledConfiguration(t *testing.T) {
	cases := map[string]struct {
		config    string
		key       string
		result    finding.Result
		wantMatch string
	}{
		"a Match block permits root":        {"PermitRootLogin no\nPasswordAuthentication no\nMatch User alice\n PermitRootLogin yes\n", "ssh.root_login_permitted", finding.ResultFail, "User alice"},
		"global and Match both permit root": {"PermitRootLogin yes\nPasswordAuthentication no\nMatch User alice\n PermitRootLogin yes\n", "ssh.root_login_permitted", finding.ResultFail, "User alice"},
		"a refused value is not judged":     {"PermitRootLogin maybe\nPasswordAuthentication no\n", "ssh.root_login_permitted", finding.ResultUnknown, ""},
		"NO in upper case disables root":    {"PermitRootLogin NO\nPasswordAuthentication no\n", "ssh.root_login_permitted", finding.ResultPass, ""},
		"Yes enables passwords":             {"PermitRootLogin no\nPasswordAuthentication Yes\n", "ssh.password_auth_enabled", finding.ResultFail, ""},
		"a quoted no disables root":         {"PermitRootLogin \"no\"\nPasswordAuthentication no\n", "ssh.root_login_permitted", finding.ResultPass, ""},
		"an included value is the one used": {"Include d/*.conf\nPermitRootLogin no\nPasswordAuthentication no\n", "ssh.password_auth_enabled", finding.ResultFail, ""},
	}
	for name, c := range cases {
		dir := writeConfig(t, map[string]string{"sshd_config": c.config, "d/50-cloud.conf": "PasswordAuthentication yes\n"})
		linux := registry.OSContext{Platform: registry.PlatformLinux, Families: []registry.Distro{registry.DistroGeneric}}
		r := &report{osCtx: linux, index: make(map[registry.FindingKey]int)}
		checkSSHDConfig(context.Background(), r, filepath.Join(dir, "sshd_config"), sshdPlatformFor(linux), Listeners{View: loopbackSSHD()})
		condition := r.result.Conditions[r.index[registry.FindingKey(c.key)]]
		if condition.Result != c.result {
			t.Errorf("%s: %s is %s (%s), want %s", name, c.key, condition.Result, condition.Reason, c.result)
			continue
		}
		reach := evidenceOfKind(condition, finding.KindListening)
		if condition.Result == finding.ResultFail && (len(reach) != 1 || factValue(reach[0], finding.FactListening) != finding.ListeningLoopbackOnly) {
			t.Errorf("%s: where sshd listens is recorded as %+v, want once, loopback-only", name, reach)
		}
		if c.wantMatch == "" {
			continue
		}
		var match string
		for _, e := range evidenceOfKind(condition, finding.KindDirective) {
			if criteria := factValue(e, finding.FactMatch); criteria != "" {
				match = criteria
			}
		}
		if match != c.wantMatch {
			t.Errorf("%s: evidence %+v, want the Match criteria %q", name, condition.Evidence, c.wantMatch)
		}
	}
}

// loopbackSSHD is a host whose port 22 is held on loopback only, by systemd
// rather than sshd, as a socket-activated sshd is, with sockets on port 22
// that are not listening and a UDP socket on 22 that sshd does not use.
func loopbackSSHD() *sockets.View {
	v := sockets.NewView([]sockets.Socket{
		{Protocol: sockets.TCP, State: sockets.StateListen, Local: "127.0.0.1:22", Scope: sockets.ScopeLoopback, Processes: []sockets.Process{{PID: 1, Name: "systemd"}}},
		{Protocol: sockets.TCP6, State: sockets.StateListen, Local: "[::1]:22", Scope: sockets.ScopeLoopback},
		{Protocol: sockets.TCP, State: sockets.StateEstablished, Local: "10.0.0.5:22", Remote: "10.0.0.9:50000", Scope: sockets.ScopeSpecific},
		{Protocol: sockets.UDP, State: sockets.StateUnconnected, Local: "0.0.0.0:22", Scope: sockets.ScopeWildcard},
		{Protocol: sockets.TCP, State: sockets.StateListen, Local: "0.0.0.0:2222", Scope: sockets.ScopeWildcard},
	})
	return &v
}

// evidenceOfKind returns the evidence of one kind a condition carries.
func evidenceOfKind(condition finding.Condition, kind finding.EvidenceKind) []finding.Evidence {
	var out []finding.Evidence
	for _, e := range condition.Evidence {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// factValue returns the value e records for name, or empty.
func factValue(e finding.Evidence, name finding.FactName) string {
	for _, f := range e.Facts {
		if f.Name == name {
			return f.Value
		}
	}
	return ""
}

// The ports sshd listens on follow sshd: every Port, the default when there is
// none, a service name as its port, and a ListenAddress replacing the set with
// its own port or every Port. Each expectation is what sshd -T printed.
func TestListeningPortsMatchSSHD(t *testing.T) {
	for config, want := range map[string]string{
		"":                                         "22",
		"Port 2200\n":                              "2200",
		"Port 2222\nPort 22\n":                     "2222 22",
		"Port ssh\n":                               "22",
		"ListenAddress 127.0.0.1:2222\n":           "2222",
		"Port 2200\nListenAddress 127.0.0.1\n":     "2200",
		"ListenAddress 127.0.0.1\nPort 2200\n":     "2200",
		"ListenAddress [::1]:2223\n":               "2223",
		"ListenAddress ::1\n":                      "22",
		"ListenAddress 127.0.0.1:2224 rdomain x\n": "2224",
	} {
		dir := writeConfig(t, map[string]string{"sshd_config": config})
		parsed, err := parseIn(t, dir)
		if err != nil {
			t.Errorf("%q: %v", config, err)
			continue
		}
		if got := strings.Join(parsed.listeningPorts(), " "); got != want {
			t.Errorf("%q: ports %q, want %q", config, got, want)
		}
	}
	dir := writeConfig(t, map[string]string{"sshd_config": "Include p.conf\n", "p.conf": "Port 2201\n"})
	if parsed, err := parseIn(t, dir); err != nil || strings.Join(parsed.listeningPorts(), " ") != "2201" {
		t.Errorf("a Port in an included file: %v, %v", parsed.listeningPorts(), err)
	}
	for _, config := range []string{"Port 22 2222\n", "Match User bob\n Port 2222\n", "Match User bob\n ListenAddress 127.0.0.1\n", "Port\n", "ListenAddress 127.0.0.1 extra\n"} {
		dir := writeConfig(t, map[string]string{"sshd_config": config})
		if _, err := parseIn(t, dir); err == nil {
			t.Errorf("%q: sshd refuses this configuration and the parser accepted it", config)
		}
	}
}

// Where sshd listens is the TCP sockets listening on its ports whoever holds
// them, loopback-only when every one is on loopback; unread sockets or an
// unread configuration leave it undetermined; a server with nothing listening
// on its ports is none.
func TestSSHDListening(t *testing.T) {
	r := &report{index: make(map[registry.FindingKey]int)}
	parse := func(config string) sshConfig {
		parsed, err := parseIn(t, writeConfig(t, map[string]string{"sshd_config": config}))
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	network := sockets.NewView(append(loopbackSSHD().Internet,
		sockets.Socket{Protocol: sockets.TCP6, State: sockets.StateListen, Local: "[::]:22", Scope: sockets.ScopeWildcard}))

	for name, c := range map[string]struct {
		config  sshConfig
		readErr error
		view    *sockets.View
		want    string
	}{
		"loopback only, held by systemd": {parse(""), nil, loopbackSSHD(), finding.ListeningLoopbackOnly},
		"also on the wildcard":           {parse(""), nil, &network, finding.ListeningNetwork},
		"on a port it names":             {parse("Port 2222\n"), nil, loopbackSSHD(), finding.ListeningNetwork},
		"nothing on its port":            {parse("Port 2022\n"), nil, loopbackSSHD(), finding.ListeningNone},
		"sockets not read":               {parse(""), nil, nil, finding.ListeningUndetermined},
		"configuration not read in full": {parse(""), errors.New("partial"), loopbackSSHD(), finding.ListeningUndetermined},
	} {
		got := sshdListening(r, c.config, c.readErr, Listeners{View: c.view, Unread: "not read"})
		if v := factValue(got, finding.FactListening); v != c.want || got.Kind != finding.KindListening {
			t.Errorf("%s: %+v, want %s", name, got, c.want)
		}
	}
	got := sshdListening(r, parse(""), nil, Listeners{View: loopbackSSHD()})
	if addresses := factValue(got, finding.FactAddresses); addresses != "tcp 127.0.0.1:22, tcp6 [::1]:22" {
		t.Errorf("addresses %q", addresses)
	}
}

// The host listens on the network when any TCP socket listens or UDP socket is
// bound beyond loopback, and on loopback only when none is.
func TestHostListening(t *testing.T) {
	r := &report{index: make(map[registry.FindingKey]int)}
	loopback := sockets.NewView([]sockets.Socket{
		{Protocol: sockets.TCP, State: sockets.StateListen, Local: "127.0.0.1:631", Scope: sockets.ScopeLoopback},
		{Protocol: sockets.TCP, State: sockets.StateEstablished, Local: "10.0.0.5:51000", Remote: "1.1.1.1:443", Scope: sockets.ScopeSpecific},
	})
	dhcp := sockets.NewView(append(loopback.Internet,
		sockets.Socket{Protocol: sockets.UDP, State: sockets.StateUnconnected, Local: "0.0.0.0:68", Scope: sockets.ScopeWildcard}))
	for view, want := range map[*sockets.View]string{&loopback: finding.ListeningLoopbackOnly, &dhcp: finding.ListeningNetwork, {}: finding.ListeningNone} {
		if got := factValue(hostListening(r, Listeners{View: view}), finding.FactListening); got != want {
			t.Errorf("host listening %s, want %s", got, want)
		}
	}
}

// On FreeBSD a directive the configuration leaves unset is judged by the
// default sshd_config(5) states, and a password is accepted through
// PasswordAuthentication or through keyboard-interactive authentication that
// PAM answers. Each case is a configuration sshd on FreeBSD 15.1 was given,
// and the rules answer as sshd admitted or refused: root, an account by its
// password, and what PermitEmptyPasswords says of an empty one.
func TestFreeBSDJudgesDefaultsAndKeyboardInteractive(t *testing.T) {
	freebsd := registry.OSContext{Platform: registry.PlatformUnix, Families: []registry.Distro{registry.DistroFreeBSD}}
	const pass, fail = finding.ResultPass, finding.ResultFail

	cases := []struct {
		name                  string
		config                string
		root, password, empty finding.Result
	}{
		{"as shipped", "AuthorizedKeysFile .ssh/authorized_keys\n", pass, fail, pass},
		{"keyboard-interactive off", "KbdInteractiveAuthentication no\n", pass, pass, pass},
		{"the deprecated alias off", "ChallengeResponseAuthentication no\n", pass, pass, pass},
		{"passwords on", "PasswordAuthentication yes\n", pass, fail, pass},
		{"both off", "KbdInteractiveAuthentication no\nPasswordAuthentication no\n", pass, pass, pass},
		{"PAM off", "UsePAM no\n", pass, pass, pass},
		{"PAM off, passwords on", "UsePAM no\nPasswordAuthentication yes\n", pass, fail, pass},
		{"empty passwords permitted", "PermitEmptyPasswords yes\nKbdInteractiveAuthentication no\n", pass, pass, fail},
		{"root permitted", "PermitRootLogin yes\nKbdInteractiveAuthentication no\n", fail, pass, pass},
		{"root by key only", "PermitRootLogin prohibit-password\nKbdInteractiveAuthentication no\n", fail, pass, pass},
		{"root refused outright", "PermitRootLogin no\nKbdInteractiveAuthentication no\n", pass, pass, pass},
		{"a Match block turns the method on", "KbdInteractiveAuthentication no\nMatch User alice\n KbdInteractiveAuthentication yes\n", pass, fail, pass},
	}
	unread := Listeners{Unread: "not read on this platform"}
	for _, c := range cases {
		dir := writeConfig(t, map[string]string{"sshd_config": c.config})
		r := &report{osCtx: freebsd, index: make(map[registry.FindingKey]int)}
		checkSSHDConfig(context.Background(), r, filepath.Join(dir, "sshd_config"), sshdPlatformFor(freebsd), unread)

		for key, want := range map[registry.FindingKey]finding.Result{
			ruleSSHRootLogin: c.root, ruleSSHPassword: c.password, ruleSSHEmptyPasswords: c.empty,
		} {
			i, ok := r.index[key]
			if !ok || r.result.Conditions[i].Result != want {
				t.Errorf("%s: %s is not %s: %+v", c.name, key, want, r.result.Conditions)
			}
		}
		for _, key := range []registry.FindingKey{ruleSSHRootLoginUnset, ruleSSHPasswordUnset} {
			if _, ok := r.index[key]; ok {
				t.Errorf("%s: %s was concluded on a platform that does not define it", c.name, key)
			}
		}
	}

	// The stock host fails by the default, and the evidence says which
	// directives let a password in and that neither is set.
	dir := writeConfig(t, map[string]string{"sshd_config": "Subsystem sftp /usr/libexec/sftp-server\n"})
	r := &report{osCtx: freebsd, index: make(map[registry.FindingKey]int)}
	checkSSHDConfig(context.Background(), r, filepath.Join(dir, "sshd_config"), sshdPlatformFor(freebsd), unread)
	way := evidenceOfKind(r.result.Conditions[r.index[ruleSSHPassword]], finding.KindDirective)
	if len(way) != 2 || way[0].Subject != directiveKeyboard || way[1].Subject != directiveUsePAM {
		t.Fatalf("the way a password gets in is recorded as %+v", way)
	}
	for _, e := range way {
		if factValue(e, finding.FactValue) != "yes" || factValue(e, finding.FactState) != sshdDefaultState {
			t.Errorf("%s is recorded as %+v, want yes by default", e.Subject, e.Facts)
		}
	}
}

// A platform that states no default leaves an unset directive as it was: not
// checked, with the rule the platform has for it, and the directives only
// FreeBSD is judged by conclude nothing there.
func TestUnsetDirectiveWithoutAStatedDefault(t *testing.T) {
	linux := registry.OSContext{Platform: registry.PlatformLinux, Families: []registry.Distro{registry.DistroGeneric}}
	dir := writeConfig(t, map[string]string{"sshd_config": "KbdInteractiveAuthentication yes\nUsePAM yes\nPermitEmptyPasswords yes\n"})
	r := &report{osCtx: linux, index: make(map[registry.FindingKey]int)}
	checkSSHDConfig(context.Background(), r, filepath.Join(dir, "sshd_config"), sshdPlatformFor(linux), Listeners{View: loopbackSSHD()})

	for key, want := range map[registry.FindingKey]finding.Result{
		ruleSSHRootLogin: finding.ResultNotChecked, ruleSSHPassword: finding.ResultNotChecked,
		ruleSSHRootLoginUnset: finding.ResultFail, ruleSSHPasswordUnset: finding.ResultFail,
	} {
		if got := r.result.Conditions[r.index[key]].Result; got != want {
			t.Errorf("%s: %s, want %s", key, got, want)
		}
	}
	if _, ok := r.index[ruleSSHEmptyPasswords]; ok {
		t.Error("the empty password rule was concluded on Linux, which does not define it")
	}
}
