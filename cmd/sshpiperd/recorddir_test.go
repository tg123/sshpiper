package main

import (
	"path/filepath"
	"testing"
)

// TestSafeJoinUserRecordDir exercises the path-traversal guard that protects
// --record-typescript-dir / --record-asciicast-dir when
// --username-as-recorddir is enabled. The downstream SSH username is fully
// attacker-controlled, so a malicious user string must never be able to
// resolve outside of the configured recording root.
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
		{name: "absolute path escapes via join", user: "/etc/passwd", wantErr: false}, // filepath.Join treats it as relative to base
		{name: "leading slashes still relative", user: "//../../evil", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := safeJoinUserRecordDir(base, tt.user)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("safeJoinUserRecordDir(%q, %q) = %q, nil; want error", base, tt.user, dir)
				}
				return
			}

			if err != nil {
				t.Fatalf("safeJoinUserRecordDir(%q, %q) unexpected error: %v", base, tt.user, err)
			}

			rel, rerr := filepath.Rel(base, dir)
			if rerr != nil {
				t.Fatalf("filepath.Rel(%q, %q) error: %v", base, dir, rerr)
			}
			if rel == ".." || (len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator)) {
				t.Fatalf("safeJoinUserRecordDir(%q, %q) = %q escapes base %q (rel=%q)", base, tt.user, dir, base, rel)
			}
		})
	}
}
