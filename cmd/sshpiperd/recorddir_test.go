package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestSafeJoinUserRecordDir exercises the lexical path-traversal guard that
// protects the per-user recording subdirectory created under
// --screen-recording-dir when --username-as-recorddir is enabled. The
// downstream SSH username is fully attacker-controlled, so a malicious user
// string must never resolve outside of the configured recording root.
//
// This lexical guard is only a first line of defense: the subdirectory name
// it returns is always subsequently created/opened through an os.Root
// scoped to the recording root (see daemon.initScreenRecording /
// setupScreenRecording), which is the actual containment boundary and also
// refuses to follow a symlink that would escape the root.
func TestSafeJoinUserRecordDir(t *testing.T) {
	base := filepath.Join(t.TempDir(), "records")

	tests := []struct {
		name    string
		user    string
		wantErr bool
	}{
		{name: "plain username", user: "alice", wantErr: false},
		{name: "username with subdirs stays inside", user: "alice/bob", wantErr: false},
		{name: "empty username resolves to base", user: "", wantErr: false},
		{name: "dot username resolves to base", user: ".", wantErr: false},
		{name: "parent traversal", user: "..", wantErr: true},
		{name: "nested parent traversal", user: "../../etc/passwd", wantErr: true},
		{name: "traversal after subdir", user: "foo/../../bar", wantErr: true},
		{name: "traversal disguised with valid prefix", user: "alice/../../evil", wantErr: true},
		{name: "absolute-looking username stays contained under base", user: "/etc/passwd", wantErr: false}, // filepath.Join treats it as relative to base, so it does not escape
		{name: "leading slashes still relative", user: "//../../evil", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rel, err := safeJoinUserRecordDir(base, tt.user)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("safeJoinUserRecordDir(%q, %q) = %q, nil; want error", base, tt.user, rel)
				}
				return
			}

			if err != nil {
				t.Fatalf("safeJoinUserRecordDir(%q, %q) unexpected error: %v", base, tt.user, err)
			}

			if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				t.Fatalf("safeJoinUserRecordDir(%q, %q) = %q escapes base %q", base, tt.user, rel, base)
			}

			// The returned name must be relative to base, and joining it
			// back onto base must stay inside base.
			joined := filepath.Join(base, rel)
			if !strings.HasPrefix(joined+string(filepath.Separator), filepath.Clean(base)+string(filepath.Separator)) {
				t.Fatalf("safeJoinUserRecordDir(%q, %q) = %q joins outside base %q", base, tt.user, rel, base)
			}
		})
	}
}
