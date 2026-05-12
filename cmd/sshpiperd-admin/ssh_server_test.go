package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tg123/sshpiper/libadmin"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

func TestSplitArgs(t *testing.T) {
	cases := []struct {
		in      string
		want    []string
		wantErr bool
	}{
		{"", []string{}, false},
		{"   ", []string{}, false},
		{"list", []string{"list"}, false},
		{"list --json", []string{"list", "--json"}, false},
		{"kill abc-123", []string{"kill", "abc-123"}, false},
		{"stream  abc   --format   asciicast", []string{"stream", "abc", "--format", "asciicast"}, false},
		{`kill "id with spaces"`, []string{"kill", "id with spaces"}, false},
		{`kill 'id with spaces'`, []string{"kill", "id with spaces"}, false},
		{`echo "a\"b"`, []string{"echo", `a"b`}, false},
		{`echo a\ b`, []string{"echo", "a b"}, false},
		{`bad "unterminated`, nil, true},
		{`bad 'unterminated`, nil, true},
		{`bad \`, nil, true},
	}

	for _, tc := range cases {
		got, err := splitArgs(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("splitArgs(%q): want error, got %v", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("splitArgs(%q): unexpected error %v", tc.in, err)
			continue
		}
		if len(got) == 0 && len(tc.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("splitArgs(%q): got %#v, want %#v", tc.in, got, tc.want)
		}
	}
}

func TestParseStringPayload(t *testing.T) {
	// SSH "string" wire format: uint32 length prefix + bytes.
	cases := []struct {
		payload []byte
		want    string
	}{
		{[]byte{0, 0, 0, 4, 'l', 'i', 's', 't'}, "list"},
		{[]byte{0, 0, 0, 0}, ""},
		{[]byte{0, 0}, ""},                  // too short
		{[]byte{0, 0, 0, 10, 'a', 'b'}, ""}, // length larger than payload
	}
	for _, tc := range cases {
		if got := parseStringPayload(tc.payload); got != tc.want {
			t.Errorf("parseStringPayload(%v): got %q, want %q", tc.payload, got, tc.want)
		}
	}
}

// generateAuthorizedKeyLine returns a freshly-generated ed25519 public key
// formatted as a single authorized_keys line (without trailing newline).
func generateAuthorizedKeyLine(t *testing.T, comment string) (string, ssh.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	if comment != "" {
		line += " " + comment
	}
	return line, sshPub
}

func writeAuthFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestAuthorizedKeysChecker_LoadsKeysAndSkipsCommentsAndBlankLines(t *testing.T) {
	line1, pub1 := generateAuthorizedKeyLine(t, "alice@example")
	line2, pub2 := generateAuthorizedKeyLine(t, "")

	content := "" +
		"# leading comment line\n" +
		"\n" +
		"   \n" +
		line1 + "\n" +
		"# inline comment between keys\n" +
		"\n" +
		line2 + "\n" +
		"# trailing comment\n"

	path := writeAuthFile(t, content)
	c, err := newAuthorizedKeysChecker(path)
	if err != nil {
		t.Fatalf("newAuthorizedKeysChecker: %v", err)
	}

	for _, k := range []ssh.PublicKey{pub1, pub2} {
		if _, err := c.callback(nil, k); err != nil {
			t.Errorf("expected key to be authorized: %v", err)
		}
	}

	_, otherPub := generateAuthorizedKeyLine(t, "")
	if _, err := c.callback(nil, otherPub); err == nil {
		t.Error("expected unknown key to be rejected")
	}
}

func TestAuthorizedKeysChecker_RejectsKeyWithOptions(t *testing.T) {
	line, _ := generateAuthorizedKeyLine(t, "")
	content := `from="10.0.0.0/8",command="echo hi" ` + line + "\n"
	path := writeAuthFile(t, content)

	_, err := newAuthorizedKeysChecker(path)
	if err == nil {
		t.Fatal("expected error for key with options, got nil")
	}
	if !strings.Contains(err.Error(), "options") {
		t.Errorf("expected error to mention options, got %v", err)
	}
}

func TestAuthorizedKeysChecker_RejectsMalformedLine(t *testing.T) {
	line, _ := generateAuthorizedKeyLine(t, "")
	content := line + "\nthis-is-not-a-key\n"
	path := writeAuthFile(t, content)

	if _, err := newAuthorizedKeysChecker(path); err == nil {
		t.Fatal("expected error for malformed line, got nil")
	}
}

func TestAuthorizedKeysChecker_EmptyFileFails(t *testing.T) {
	path := writeAuthFile(t, "# only comments\n\n  \n")
	_, err := newAuthorizedKeysChecker(path)
	if err == nil {
		t.Fatal("expected error for file with no keys, got nil")
	}
	if !strings.Contains(err.Error(), "no public keys") {
		t.Errorf("expected error to mention missing keys, got %v", err)
	}
}

func TestAuthorizedKeysChecker_MissingFile(t *testing.T) {
	if _, err := newAuthorizedKeysChecker(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestInheritedGlobalArgsOnlyEmitsExplicitFlags(t *testing.T) {
	app := newApp(true)
	app.Action = func(c *cli.Context) error {
		got := inheritedGlobalArgs(c)
		if len(got) != 0 {
			t.Errorf("expected no inherited args when nothing set, got %v", got)
		}
		return nil
	}
	if err := app.Run([]string{"sshpiperd-admin"}); err != nil {
		t.Fatalf("run: %v", err)
	}

	app2 := newApp(true)
	app2.Action = func(c *cli.Context) error {
		got := inheritedGlobalArgs(c)
		want := []string{
			"--sshpiperd", "127.0.0.1:8082",
			"--insecure=false",
			"--timeout", "30s",
			"--log-level", "debug",
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("inheritedGlobalArgs: got %v, want %v", got, want)
		}
		return nil
	}
	args := []string{
		"sshpiperd-admin",
		"--sshpiperd", "127.0.0.1:8082",
		"--insecure=false",
		"--timeout", "30s",
		"--log-level", "debug",
	}
	if err := app2.Run(args); err != nil {
		t.Fatalf("run: %v", err)
	}
}

func TestStreamHandlerAsciicastSingleHeaderAndChannelFilter(t *testing.T) {
	var buf strings.Builder
	h := streamHandler("asciicast", &buf)

	mkHeader := func(ch uint32, w, hgt int32) *libadmin.SessionFrame {
		return &libadmin.SessionFrame{Frame: &libadmin.SessionFrame_Header{Header: &libadmin.AsciicastHeader{
			Width: w, Height: hgt, Timestamp: 1700000000, ChannelId: ch,
		}}}
	}
	mkEvent := func(ch uint32, kind, data string) *libadmin.SessionFrame {
		return &libadmin.SessionFrame{Frame: &libadmin.SessionFrame_Event{Event: &libadmin.AsciicastEvent{
			Kind: kind, Data: []byte(data), ChannelId: ch,
		}}}
	}

	// First header locks channel 1.
	if err := h(mkHeader(1, 80, 24)); err != nil {
		t.Fatal(err)
	}
	// Header for a different channel: dropped.
	if err := h(mkHeader(2, 100, 30)); err != nil {
		t.Fatal(err)
	}
	// Event on the locked channel: emitted.
	if err := h(mkEvent(1, "o", "hi")); err != nil {
		t.Fatal(err)
	}
	// Event on a different channel: dropped.
	if err := h(mkEvent(2, "o", "nope")); err != nil {
		t.Fatal(err)
	}
	// Subsequent header for the locked channel -> resize event.
	if err := h(mkHeader(1, 120, 40)); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines (header + event + resize), got %d: %q", len(lines), buf.String())
	}
	if !strings.HasPrefix(lines[0], `{`) || !strings.Contains(lines[0], `"version":2`) {
		t.Errorf("expected header object first, got %q", lines[0])
	}
	if !strings.Contains(lines[1], `"o"`) || !strings.Contains(lines[1], `"hi"`) {
		t.Errorf("expected output event second, got %q", lines[1])
	}
	if !strings.Contains(lines[2], `"r"`) || !strings.Contains(lines[2], `"120x40"`) {
		t.Errorf("expected resize event third, got %q", lines[2])
	}
	if strings.Contains(buf.String(), "nope") {
		t.Errorf("dropped-channel event should not be emitted: %q", buf.String())
	}
}
