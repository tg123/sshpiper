package plugin

import (
	"golang.org/x/term"
	"io"
	"os"
)

// checkIfTerminal returns whether the given file descriptor is a terminal.
func checkIfTerminal(w io.Writer) bool {
	switch v := w.(type) {
	case *os.File:
		return term.IsTerminal(int(v.Fd()))
	default:
		return false
	}
}
