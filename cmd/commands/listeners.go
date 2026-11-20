// cmd/commands/listeners.go

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/internal/selection"
)

// newListenersCmd returns the command that lists the host's sockets.
func newListenersCmd() *cobra.Command {
	return newInventoryCmd(standaloneModule{
		use:   selection.NameListeners,
		short: "List the host's sockets and the processes holding them",
		long: `The listeners command lists every socket the host reports, in every state: listening and connected TCP, UDP, raw, unix-domain and packet sockets, with the address each is bound to, its peer, and the processes holding it with their executables and accounts. It reads the host's own tables and connects to nothing.

Reading which process holds another user's socket needs privilege. A run without it says so for each socket it could not attribute; run with sudo, or from an administrator terminal, to see them all. A saved report records the remote end of every connection, and so who the host was talking to.

The report opens in the results browser on a terminal, with the same layout as an audit.`,
		example: `  # Open the host's sockets in the results browser
  owatch listeners

  # Print them as text instead of opening the results browser
  owatch listeners --plain

  # Attribute every socket to its process
  sudo owatch listeners --plain

  # Save them to a directory in JSON format
  owatch listeners -o json --report-file /path/to/reports`,
	})
}
