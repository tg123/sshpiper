package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeConn struct {
	user string
}

func (f fakeConn) User() string            { return f.user }
func (fakeConn) RemoteAddr() string        { return "" }
func (fakeConn) UniqueID() string          { return "" }
func (fakeConn) GetMeta(key string) string { return "" }

type workingdirFactory = workdingdirFactory

func TestIsUsernameSecure(t *testing.T) {
	cases := []struct {
		name string
		user string
		want bool
	}{
		{name: "simple", user: "alice", want: true},
		{name: "withDash", user: "a-user", want: true},
		{name: "withUnderscore", user: "a_user", want: true},
		{name: "leadingUnderscore", user: "_alice", want: true},
		{name: "withNumber", user: "a1", want: true},
		{name: "leadingDash", user: "-alice", want: false},
		{name: "startsWithNumber", user: "1alice", want: false},
		{name: "containsUppercase", user: "Alice", want: false},
		{name: "tooLong", user: strings.Repeat("a", 33), want: false},
		{name: "empty", user: "", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isUsernameSecure(tc.user); got != tc.want {
				t.Fatalf("isUsernameSecure(%q) = %v, want %v", tc.user, got, tc.want)
			}
		})
	}
}

func TestParseUpstreamFile(t *testing.T) {
	t.Run("parseUserAndHost", func(t *testing.T) {
		host, user, err := parseUpstreamFile("bob@example.com:2200\n")
		if err != nil {
			t.Fatalf("parseUpstreamFile returned error: %v", err)
		}

		if host != "example.com:2200" || user != "bob" {
			t.Fatalf("unexpected parse result host=%q user=%q", host, user)
		}
	})

	t.Run("skipCommentsAndWhitespace", func(t *testing.T) {
		data := "# comment line\n\nexample.com\n"
		host, user, err := parseUpstreamFile(data)
		if err != nil {
			t.Fatalf("parseUpstreamFile returned error: %v", err)
		}

		if host != "example.com" || user != "" {
			t.Fatalf("unexpected parse result host=%q user=%q", host, user)
		}
	})

	t.Run("invalidEntryReturnsError", func(t *testing.T) {
		if _, _, err := parseUpstreamFile("bad host\n"); err == nil {
			t.Fatal("expected error for invalid host but got nil")
		}
	})

	t.Run("emptyContentReturnsError", func(t *testing.T) {
		if _, _, err := parseUpstreamFile("# only comment\n"); err == nil {
			t.Fatal("expected error for empty content but got nil")
		}
	})
}

func TestWorkingdirPermissionChecks(t *testing.T) {
	tmp := t.TempDir()
	w := &workingdir{Path: tmp}

	secureFile := "secure"
	if err := os.WriteFile(filepath.Join(tmp, secureFile), []byte("ok"), 0o400); err != nil {
		t.Fatalf("failed to write secure file: %v", err)
	}

	if _, err := w.Readfile(secureFile); err != nil {
		t.Fatalf("Readfile on secure file returned error: %v", err)
	}

	openFile := "open"
	if err := os.WriteFile(filepath.Join(tmp, openFile), []byte("nope"), 0o644); err != nil {
		t.Fatalf("failed to write open file: %v", err)
	}

	if err := w.checkPerm(openFile); err == nil {
		t.Fatal("expected error for file with open permission, got nil")
	}

	w.NoCheckPerm = true
	if _, err := w.Readfile(openFile); err != nil {
		t.Fatalf("Readfile should ignore permission check when NoCheckPerm is true, got error: %v", err)
	}
}

func TestWorkingdirFactoryListPipe(t *testing.T) {
	root := t.TempDir()
	user := "alice"
	userDir := filepath.Join(root, user)

	if err := os.MkdirAll(userDir, 0o700); err != nil {
		t.Fatalf("failed to create user dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(userDir, userUpstreamFile), []byte("bob@example.com:2200\n"), 0o400); err != nil {
		t.Fatalf("failed to write upstream file: %v", err)
	}

	// presence of both files should cause From to return public key wrapper
	if err := os.WriteFile(filepath.Join(userDir, userAuthorizedKeysFile), []byte("key"), 0o400); err != nil {
		t.Fatalf("failed to write authorized_keys: %v", err)
	}
	if err := os.WriteFile(filepath.Join(userDir, userKeyFile), []byte("private"), 0o400); err != nil {
		t.Fatalf("failed to write id_rsa: %v", err)
	}

	fac := workingdirFactory{
		root:             root,
		allowBadUsername: true,
		noCheckPerm:      false,
		strictHostKey:    true,
		recursiveSearch:  false,
	}

	pipes, err := fac.listPipe(fakeConn{user: user})
	if err != nil {
		t.Fatalf("listPipe returned error: %v", err)
	}

	if len(pipes) != 1 {
		t.Fatalf("expected 1 pipe, got %d", len(pipes))
	}

	pipe, ok := pipes[0].(*skelpipeWrapper)
	if !ok {
		t.Fatalf("unexpected pipe type %T", pipes[0])
	}

	if pipe.host != "example.com:2200" || pipe.username != "bob" {
		t.Fatalf("unexpected upstream host/user %q/%q", pipe.host, pipe.username)
	}

	if !pipe.dir.Strict {
		t.Fatal("expected Strict flag to propagate to workingdir")
	}

	from := pipe.From()
	if len(from) != 1 {
		t.Fatalf("expected 1 From entry, got %d", len(from))
	}

	pub, ok := from[0].(*skelpipePublicKeyWrapper)
	if !ok {
		t.Fatalf("expected skelpipePublicKeyWrapper, got %T", from[0])
	}

	to, err := pub.MatchConn(fakeConn{user: user})
	if err != nil {
		t.Fatalf("MatchConn returned error: %v", err)
	}

	private, ok := to.(*skelpipeToPrivateKeyWrapper)
	if !ok {
		t.Fatalf("expected skelpipeToPrivateKeyWrapper, got %T", to)
	}

	if private.IgnoreHostKey(fakeConn{user: user}) {
		t.Fatal("expected IgnoreHostKey to respect strict host key settings")
	}
}
