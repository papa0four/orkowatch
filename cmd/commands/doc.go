// cmd/commands/doc.go

// Package cmd defines the owatch command tree: the root command, the
// individual module commands, and all, which composes the modules into a
// single run. Execute is the binary's sole error-reporting point; errors go
// to stderr so they cannot interleave with report output.
package cmd
