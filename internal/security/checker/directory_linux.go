//go:build linux

// internal/security/checker/directory_linux.go

package checker

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// checkDirectoryClients records each directory client's configuration and
// what the name service switch and the PAM stack wire to it, then judges the
// configuration of the clients whose rules are defined. What could not be read
// is stated, so reduced coverage is not read as no wiring.
func (u *UnixUserChecker) checkDirectoryClients(ctx context.Context, r *report) {
	root := os.DirFS("/")
	clients := directoryClients(u.osCtx.Families)
	nss, problems := readNSSWiring(root, u.osCtx.Families)
	stack := readPAMStack(root, pamLayoutFor(u.osCtx.Families), clientModules(clients))
	for _, problem := range append(problems, stack.problems...) {
		r.note(finding.SymbolWarning, "%s", problem)
	}
	recordDirectoryClients(r, root, clients, nss, stack)
	recordSSSD(r, root, sssdHost{
		version: func() (sssdVersion, error) { return installedSSSD(ctx) },
		owner: func(info fs.FileInfo) (uint32, uint32, bool) {
			uid, gid, _, ok := fileIdentity(info)
			return uid, gid, ok
		},
	})
}

// installedSSSD asks the sssd binary for its release. The configuration does
// not state it, and the defaults and file ownership the manual gives differ
// between releases.
func installedSSSD(ctx context.Context) (sssdVersion, error) {
	output, err := exec.CommandContext(ctx, "sssd", "--version").Output()
	if err != nil {
		return sssdVersion{}, fmt.Errorf("sssd --version: %w", err)
	}
	return parseSSSDVersion(string(output))
}
