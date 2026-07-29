//go:build full || e2e

package main

import (
	"fmt"
	"net/url"
	"path/filepath"
	"runtime"
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
		p := fileURIPath(u, runtime.GOOS)
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("revtunnel: --session-store %q is missing a path", spec)
		}
		return newFileStore(p)
	default:
		return nil, fmt.Errorf("revtunnel: --session-store scheme %q not supported (want memory:// or file://path)", u.Scheme)
	}
}

// fileURIPath converts the path portion of a file URI to an OS-native path.
// In particular, canonical Windows file URIs use file:///C:/dir; URL parsing
// yields /C:/dir, so the URI-only leading slash must be removed before the
// separators are converted.
func fileURIPath(u *url.URL, goos string) string {
	// Accept file:///abs/path (Path), file://relative/path (Host+Path), and
	// file:relative (Opaque).
	p := u.Path
	if u.Host != "" {
		p = u.Host + p
	}
	if u.Opaque != "" {
		p = u.Opaque
	}
	if goos == "windows" {
		if len(p) >= 3 && p[0] == '/' && isASCIILetter(p[1]) && p[2] == ':' {
			p = p[1:]
		}
		// filepath.FromSlash follows the host OS, so use an explicit
		// conversion to make this helper testable on non-Windows builders.
		return strings.ReplaceAll(p, "/", `\`)
	}
	return filepath.FromSlash(p)
}

func isASCIILetter(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}
