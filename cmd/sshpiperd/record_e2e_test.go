package main

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// wireRecordingPiper replicates the screen-recording wiring in (*daemon).run
// verbatim (including the path-traversal guard added for
// --username-as-recorddir), so tests exercise the exact same code paths that
// production traffic uses. It returns once the piped session ends, or
// immediately if the recording dir is rejected (mirroring daemon.go's early
// return).
func wireRecordingPiper(t *testing.T, p *ssh.PiperConn, d *daemon) {
	t.Helper()

	uphookchain := &hookChain{}
	downhookchain := &hookChain{}

	if d.recorddir != "" {
		var recorddir string
		if d.usernameAsRecorddir {
			user := p.DownstreamConnMeta().User()
			dir, err := safeJoinUserRecordDir(d.recorddir, user)
			if err != nil {
				t.Logf("rejected screen recording dir for user %q: %v", user, err)
				return
			}
			recorddir = dir
		} else {
			recorddir = filepath.Join(d.recorddir, "conn")
		}

		if err := os.MkdirAll(recorddir, 0o700); err != nil {
			t.Errorf("cannot create screen recording dir: %v", err)
			return
		}

		switch d.recordfmt {
		case "asciicast":
			recorder := newAsciicastLogger(recorddir, "")
			defer recorder.Close()

			uphookchain.append(ssh.InspectPacketHook(recorder.uphook))
			downhookchain.append(ssh.InspectPacketHook(recorder.downhook))
		case "typescript":
			recorder, err := newFilePtyLogger(recorddir)
			if err != nil {
				t.Errorf("cannot create screen recording logger: %v", err)
				return
			}
			defer recorder.Close()

			uphookchain.append(ssh.InspectPacketHook(recorder.loggingTty))
		}
	}

	_ = p.WaitWithHook(uphookchain.hook(), downhookchain.hook())
}

// startRecordingPiper starts the in-process sshpiper-style listener wired
// exactly like daemon.go wires screen recording, proxying to an in-process
// fake upstream sshd. It returns the piper listener address and a channel
// that is closed once the (single) accepted connection's handling goroutine
// has fully returned (including recorder.Close()).
func startRecordingPiper(t *testing.T, d *daemon) (addr string, done chan struct{}) {
	t.Helper()

	hostKey := genHostKey(t)

	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	t.Cleanup(func() { upstreamLn.Close() })
	go runFakeUpstream(t, upstreamLn, hostKey, make(chan envKV, 8))

	piperLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("piper listen: %v", err)
	}
	t.Cleanup(func() { piperLn.Close() })

	piperCfg := &ssh.PiperConfig{
		NoClientAuthCallback: func(_ ssh.ConnMetadata, _ ssh.ChallengeContext) (*ssh.Upstream, error) {
			c, err := net.Dial("tcp", upstreamLn.Addr().String())
			if err != nil {
				return nil, err
			}
			return &ssh.Upstream{
				Conn: c,
				ClientConfig: ssh.ClientConfig{
					User:            "u",
					Auth:            []ssh.AuthMethod{ssh.NoneAuth()},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				},
			}, nil
		},
	}
	piperCfg.AddHostKey(hostKey)

	done = make(chan struct{})
	go func() {
		defer close(done)

		c, err := piperLn.Accept()
		if err != nil {
			return
		}

		p, err := ssh.NewSSHPiperConn(c, piperCfg)
		if err != nil {
			t.Errorf("piper handshake: %v", err)
			return
		}
		defer p.Close()

		wireRecordingPiper(t, p, d)
	}()

	return piperLn.Addr().String(), done
}

// runClientShellSession dials addr as user, opens a shell session, writes
// payload to stdin, drains stdout, and closes the connection. It is used to
// drive traffic through the recording hooks the same way a real SSH client
// would.
func runClientShellSession(t *testing.T, addr, user, payload string) error {
	t.Helper()

	conn, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.NoneAuth()},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	if err := session.Shell(); err != nil {
		return err
	}

	_, _ = stdin.Write([]byte(payload))
	stdin.Close()
	_, _ = io.ReadAll(stdout)

	return nil
}

func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server-side connection handler to finish")
	}
}

// TestDaemonScreenRecordingEndToEnd verifies that, wired exactly the way
// daemon.go wires it, a real shell session typed by a client is actually
// captured on disk under recorddir/<username>/ for both supported formats.
func TestDaemonScreenRecordingEndToEnd(t *testing.T) {
	const payload = "hello-recording-e2e"

	t.Run("asciicast", func(t *testing.T) {
		recordRoot := t.TempDir()
		d := &daemon{
			recorddir:           recordRoot,
			recordfmt:           "asciicast",
			usernameAsRecorddir: true,
		}

		addr, done := startRecordingPiper(t, d)

		if err := runClientShellSession(t, addr, "alice", payload); err != nil {
			t.Fatalf("client session: %v", err)
		}
		waitDone(t, done)

		userDir := filepath.Join(recordRoot, "alice")
		entries, err := os.ReadDir(userDir)
		if err != nil {
			t.Fatalf("read user record dir: %v", err)
		}

		var castFile string
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".cast") {
				castFile = filepath.Join(userDir, e.Name())
			}
		}
		if castFile == "" {
			t.Fatalf("no .cast file found in %v, entries: %v", userDir, entries)
		}

		content, err := os.ReadFile(castFile)
		if err != nil {
			t.Fatalf("read cast file: %v", err)
		}

		lines := strings.Split(strings.TrimSpace(string(content)), "\n")
		if len(lines) < 1 {
			t.Fatalf("cast file has no lines: %q", content)
		}

		var header struct {
			Version int `json:"version"`
			Width   int `json:"width"`
			Height  int `json:"height"`
		}
		if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
			t.Fatalf("cast header not valid json: %v (line=%q)", err, lines[0])
		}
		if header.Version != 2 {
			t.Errorf("cast header version = %d, want 2", header.Version)
		}

		if !strings.Contains(string(content), payload) {
			t.Errorf("cast file does not contain typed payload %q; content: %q", payload, content)
		}
	})

	t.Run("typescript", func(t *testing.T) {
		recordRoot := t.TempDir()
		d := &daemon{
			recorddir:           recordRoot,
			recordfmt:           "typescript",
			usernameAsRecorddir: true,
		}

		addr, done := startRecordingPiper(t, d)

		if err := runClientShellSession(t, addr, "bob", payload); err != nil {
			t.Fatalf("client session: %v", err)
		}
		waitDone(t, done)

		userDir := filepath.Join(recordRoot, "bob")
		entries, err := os.ReadDir(userDir)
		if err != nil {
			t.Fatalf("read user record dir: %v", err)
		}

		var typescriptFile, timingFile string
		for _, e := range entries {
			switch {
			case strings.HasSuffix(e.Name(), ".typescript"):
				typescriptFile = filepath.Join(userDir, e.Name())
			case strings.HasSuffix(e.Name(), ".timing"):
				timingFile = filepath.Join(userDir, e.Name())
			}
		}
		if typescriptFile == "" || timingFile == "" {
			t.Fatalf("expected .typescript and .timing files in %v, entries: %v", userDir, entries)
		}

		content, err := os.ReadFile(typescriptFile)
		if err != nil {
			t.Fatalf("read typescript file: %v", err)
		}
		if !strings.Contains(string(content), payload) {
			t.Errorf("typescript file does not contain typed payload %q; content: %q", payload, content)
		}
		if !strings.Contains(string(content), "Script started on") || !strings.Contains(string(content), "Script done on") {
			t.Errorf("typescript file missing script start/done banners: %q", content)
		}

		timing, err := os.ReadFile(timingFile)
		if err != nil {
			t.Fatalf("read timing file: %v", err)
		}
		if len(strings.TrimSpace(string(timing))) == 0 {
			t.Errorf("timing file is empty, want at least one timing entry")
		}
	})
}

// TestDaemonScreenRecordingRejectsPathTraversalUsername is a regression test
// for the recorddir path-traversal fix: a malicious downstream username
// containing ".." must not be able to make the per-user recording directory
// resolve outside of the configured --record-*-dir root, and no directory or
// recording file must be created as a result of the attempt.
func TestDaemonScreenRecordingRejectsPathTraversalUsername(t *testing.T) {
	recordParent := t.TempDir()
	recordRoot := filepath.Join(recordParent, "records")
	if err := os.MkdirAll(recordRoot, 0o700); err != nil {
		t.Fatalf("mkdir recordRoot: %v", err)
	}

	maliciousUsers := []string{
		"../../evil",
		"..",
		"../outside",
	}

	for _, user := range maliciousUsers {
		d := &daemon{
			recorddir:           recordRoot,
			recordfmt:           "asciicast",
			usernameAsRecorddir: true,
		}

		addr, done := startRecordingPiper(t, d)

		// The SSH/piper handshake itself succeeds (auth is NoClientAuth);
		// the daemon only rejects once it resolves the recording dir, so a
		// dial error here is not expected, but session I/O may fail once the
		// server tears the connection down. Either way we only assert on
		// what ended up on disk below.
		_ = runClientShellSession(t, addr, user, "should-not-be-recorded")

		waitDone(t, done)
	}

	// Nothing should have escaped into the parent of recordRoot.
	parentEntries, err := os.ReadDir(recordParent)
	if err != nil {
		t.Fatalf("read record parent dir: %v", err)
	}
	if len(parentEntries) != 1 || parentEntries[0].Name() != filepath.Base(recordRoot) {
		names := make([]string, 0, len(parentEntries))
		for _, e := range parentEntries {
			names = append(names, e.Name())
		}
		t.Fatalf("unexpected entries escaped into parent of recordRoot: %v", names)
	}

	// And nothing should have been created inside recordRoot either, since
	// every attempted username was rejected before mkdir/recording started.
	rootEntries, err := os.ReadDir(recordRoot)
	if err != nil {
		t.Fatalf("read recordRoot: %v", err)
	}
	if len(rootEntries) != 0 {
		names := make([]string, 0, len(rootEntries))
		for _, e := range rootEntries {
			names = append(names, e.Name())
		}
		t.Fatalf("recordRoot should remain empty, found: %v", names)
	}
}
