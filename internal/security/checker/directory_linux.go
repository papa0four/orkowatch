//go:build linux

// internal/security/checker/directory_linux.go

package checker

import (
	"os"

	"github.com/papa0four/orkowatch/internal/security/finding"
)

// checkDirectoryClients records each directory client's configuration and
// what the name service switch and the PAM stack wire to it. What could not be
// read is stated, so reduced coverage is not read as no wiring.
func (u *UnixUserChecker) checkDirectoryClients(r *report) {
	root := os.DirFS("/")
	clients := directoryClients(u.osCtx.Families)
	nss, problems := readNSSWiring(root, u.osCtx.Families)
	stack := readPAMStack(root, pamLayoutFor(u.osCtx.Families), clientModules(clients))
	for _, problem := range append(problems, stack.problems...) {
		r.note(finding.SymbolWarning, "%s", problem)
	}
	recordDirectoryClients(r, root, clients, nss, stack)
}
