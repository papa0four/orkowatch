//go:build windows

// internal/elevation/elevated_windows.go

package elevation

import "golang.org/x/sys/windows"

// Elevated reports whether the process holds an elevated token, where it can
// write anywhere and a mistake in what it trusts is a privileged one. It is
// the question for guarding a write, and errs toward yes: a token restricted
// from an elevated one still reports elevated.
func Elevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// AdministratorInEffect reports whether the process holds the Administrators
// group in effect, which is what an elevated run adds. It is the question for
// telling a user whether elevating would let a run see more, where Elevated
// would mislead: a token restricted from an elevated one, as runas /trustlevel
// makes, still reports elevated while its Administrators group is deny-only.
// When membership cannot be checked the answer is no, so the advice is to
// elevate rather than a claim that elevation would not help.
func AdministratorInEffect() bool {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	member, err := windows.Token(0).IsMember(admins)
	return err == nil && member
}
