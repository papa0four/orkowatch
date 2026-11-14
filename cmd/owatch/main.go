// cmd/owatch/main.go

// Command owatch is a cross-platform host security auditing CLI. It gathers
// OS fingerprint and installed-software inventory, runs configuration audit
// checks, and reports findings as text, JSON, or YAML.
package main

import (
	cmd "github.com/papa0four/orkowatch/cmd/commands"
)

func main() {
	cmd.Execute()
}
