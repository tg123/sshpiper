package plugin

import (
	"io"
	"os"

	"golang.org/x/term"
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
