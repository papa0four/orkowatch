//go:build darwin || openbsd || netbsd

// internal/security/checker/firewall_unsupported.go

package checker

// firewallTools lists none: no packet filter of these platforms has been
// observed on a host here, and they define no firewall rule, so the check is
// not run on them.
func firewallTools() []firewallTool { return nil }
