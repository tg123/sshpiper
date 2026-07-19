//go:build full || e2e

package main

import (
	"fmt"
	"net/url"
	"strings"
)

// openSessionStore parses the --session-store flag value into a concrete
// implementation. Supported forms:
//
//	memory://         (default; everything kept in process memory)
//	file:///abs/path  or  file://relative/path
//
// An empty spec defaults to in-memory.
func openSessionStore(spec string) (sessionStore, error) {
	if spec == "" || spec == "memory://" || spec == "memory" {
		return newMemoryStore(), nil
	}
	u, err := url.Parse(spec)
	if err != nil {
		return nil, fmt.Errorf("revtunnel: invalid --session-store %q: %w", spec, err)
	}
	switch u.Scheme {
	case "memory":
		return newMemoryStore(), nil
	case "file":
		// Accept file:///abs/path (Path) and file://relative/path (Host+Path)
		// and file:relative (Opaque).
		p := u.Path
		if u.Host != "" {
			p = u.Host + p
		}
		if u.Opaque != "" {
			p = u.Opaque
		}
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("revtunnel: --session-store %q is missing a path", spec)
		}
		return newFileStore(p)
	default:
		return nil, fmt.Errorf("revtunnel: --session-store scheme %q not supported (want memory:// or file://path)", u.Scheme)
	}
}
