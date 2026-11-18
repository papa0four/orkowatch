// internal/security/checker/nsswitch.go

package checker

import (
	"bufio"
	"bytes"
	"slices"
	"strconv"
	"strings"
)

// nssLine is one database line of the name service switch: the database, the
// line it is on, and the services it names in the order they are queried.
type nssLine struct {
	database string
	line     int
	value    string
	services []string
}

// readNSSwitch returns the lines of an nsswitch.conf that configure one of
// databases. nsswitch.conf(5): the first column is the database name, and the
// remaining columns are services in the order they are queried, each
// optionally followed by an [STATUS=ACTION] item. Text after # is a comment,
// as every distribution's own file relies on.
func readNSSwitch(data []byte, databases []string) []nssLine {
	var out []nssLine
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for line := 1; scanner.Scan(); line++ {
		text, _, _ := strings.Cut(scanner.Text(), "#")
		database, rest, ok := strings.Cut(text, ":")
		database = strings.TrimSpace(database)
		if !ok || !slices.Contains(databases, database) {
			continue
		}
		rest = strings.TrimSpace(rest)
		out = append(out, nssLine{database: database, line: line, value: rest, services: nssServices(rest)})
	}
	return out
}

// nssServices returns the services a database line names, without the
// actions between them. An action is enclosed in brackets and may hold
// spaces.
func nssServices(value string) []string {
	var services []string
	for value != "" {
		if value[0] == '[' {
			end := strings.IndexByte(value, ']')
			if end < 0 {
				break
			}
			value = strings.TrimLeft(value[end+1:], " \t")
			continue
		}
		end := strings.IndexAny(value, " \t[")
		if end < 0 {
			end = len(value)
		}
		services = append(services, value[:end])
		value = strings.TrimLeft(value[end:], " \t")
	}
	return services
}

// lineRef names a line of a file as path:line.
func lineRef(path string, line int) string {
	return path + ":" + strconv.Itoa(line)
}
