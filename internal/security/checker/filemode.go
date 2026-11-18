// internal/security/checker/filemode.go

package checker

import "io/fs"

// formatMode renders mode the way ls does: a type character followed by nine
// permission characters, with the setuid, setgid and sticky bits shown in the
// execute position of their triad and capitalized when execute is not set.
// Go's own FileMode.String prefixes those bits instead, rendering a setuid
// binary as "urwxr-xr-x" where an operator reading a security report expects
// "-rwsr-xr-x".
func formatMode(mode fs.FileMode) string {
	out := []byte("----------")

	switch {
	case mode&fs.ModeDir != 0:
		out[0] = 'd'
	case mode&fs.ModeSymlink != 0:
		out[0] = 'l'
	}

	const permChars = "rwxrwxrwx"
	perm := mode.Perm()
	for i := range permChars {
		if perm&(1<<(len(permChars)-1-i)) != 0 {
			out[i+1] = permChars[i]
		}
	}

	special := []struct {
		pos   int
		bit   fs.FileMode
		withX byte
		noX   byte
	}{
		{3, fs.ModeSetuid, 's', 'S'},
		{6, fs.ModeSetgid, 's', 'S'},
		{9, fs.ModeSticky, 't', 'T'},
	}
	for _, sp := range special {
		if mode&sp.bit == 0 {
			continue
		}
		if out[sp.pos] == 'x' {
			out[sp.pos] = sp.withX
			continue
		}
		out[sp.pos] = sp.noX
	}

	return string(out)
}
