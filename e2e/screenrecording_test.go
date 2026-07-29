package e2e_test

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

// createFakeEchoSshServer starts a minimal in-process SSH server (reusing
// the same test host key as createFakeSshServer in grpcplugin_test.go) that
// accepts any username/password and echoes back any data written to a
// "session" channel. It stands in for a real upstream sshd so the screen
// recording e2e tests do not depend on a real system user account and can
// freely use arbitrary — including malicious, path-traversal-attempting —
// downstream usernames.
func createFakeEchoSshServer(t *testing.T) net.Listener {
	t.Helper()

	config := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, _ []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	config.SetDefaults()
	private, err := ssh.ParsePrivateKey([]byte(testprivatekey))
	if err != nil {
		t.Fatalf("failed to parse test private key: %v", err)
	}
	config.AddHostKey(private)

	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("failed to listen for fake upstream: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()

				_, chans, reqs, err := ssh.NewServerConn(c, config)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)

				for nc := range chans {
					if nc.ChannelType() != "session" {
						_ = nc.Reject(ssh.UnknownChannelType, "")
						continue
					}

					ch, in, err := nc.Accept()
					if err != nil {
						continue
					}

					go func(in <-chan *ssh.Request) {
						for req := range in {
							if req.WantReply {
								_ = req.Reply(true, nil)
							}
						}
					}(in)

					// Echo: whatever the client writes to the channel
					// (stdin) is written straight back on the same channel
					// (stdout), exactly like the fake upstream used in the
					// unit-level e2e test in cmd/sshpiperd. This is what
					// makes the recorded output deterministic and
					// verifiable from the client side.
					go func(ch ssh.Channel) {
						defer ch.Close()
						_, _ = io.Copy(ch, ch)
					}(ch)
				}
			}(c)
		}
	}()

	return l
}

// recordingSession dials piperAddr as user (which may be a malicious,
// path-traversal-attempting username) through the real sshpiperd binary,
// opens a shell session, writes payload to it, and waits for the upstream
// echo server to reflect it back — proving the recording hooks observed
// live traffic, not just the request. Every step tolerates errors: when the
// daemon intentionally tears down the connection (e.g. it rejects the
// username for recording), dial/session/shell calls are expected to fail or
// hang up early, and callers only care about what ends up on disk.
func recordingSession(t *testing.T, piperAddr, user, payload string) {
	t.Helper()

	client, err := ssh.Dial("tcp", piperAddr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password("anypass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         waitTimeout,
	})
	if err != nil {
		t.Logf("dial piper as %q: %v (may be expected)", user, err)
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Logf("new session as %q: %v (may be expected)", user, err)
		return
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		t.Logf("stdin pipe as %q: %v", user, err)
		return
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Logf("stdout pipe as %q: %v", user, err)
		return
	}

	if err := session.Shell(); err != nil {
		t.Logf("shell as %q: %v (may be expected)", user, err)
		return
	}

	_, _ = stdin.Write([]byte(payload))
	_ = stdin.Close()

	done := make(chan struct{})
	go func() {
		_, _ = io.ReadAll(stdout)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(waitTimeout):
	}
}

// findFileWithSuffix walks dir looking for the first regular file whose
// name has the given suffix, returning its path and content. It fails the
// test if none is found.
func findFileWithSuffix(t *testing.T, dir, suffix string) (path, content string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %v: %v", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), suffix) {
			continue
		}
		p := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read file %v: %v", p, err)
		}
		return p, string(b)
	}
	t.Fatalf("no *%v file found in %v, entries: %v", suffix, dir, entries)
	return "", ""
}

// TestScreenRecordingE2E starts the real sshpiperd binary (not an
// in-process stub), wired with --screen-recording-dir /
// --screen-recording-format / --username-as-recorddir exactly as an operator
// would configure it, drives an actual SSH session against it with the
// golang.org/x/crypto/ssh client library, and asserts that the
// typed/echoed session content is genuinely captured to disk, for both
// supported recording formats.
func TestScreenRecordingE2E(t *testing.T) {
	upstream := createFakeEchoSshServer(t)

	for _, format := range []string{"asciicast", "typescript"} {
		t.Run(format, func(t *testing.T) {
			recordDir := t.TempDir()
			piperaddr, piperport := nextAvailablePiperAddress()

			piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
				"-p", piperport,
				"--screen-recording-dir", recordDir,
				"--screen-recording-format", format,
				"--username-as-recorddir",
				"/sshpiperd/plugins/fixed",
				"--target", upstream.Addr().String(),
			)
			if err != nil {
				t.Fatalf("failed to run sshpiperd: %v", err)
			}
			t.Cleanup(func() { killCmd(piper) })
			waitForEndpointReady(piperaddr)

			user := "user-" + uuid.New().String()[:8]
			payload := "hello-" + uuid.New().String()

			recordingSession(t, piperaddr, user, payload)

			// Give the recorder time to flush/close its files after the
			// session ends.
			time.Sleep(time.Second)

			userDir := filepath.Join(recordDir, user)
			var suffix string
			switch format {
			case "asciicast":
				suffix = ".cast"
			case "typescript":
				suffix = ".typescript"
			}

			_, content := findFileWithSuffix(t, userDir, suffix)
			if !strings.Contains(content, payload) {
				t.Errorf("recording does not contain payload %q; content: %q", payload, content)
			}

			if format == "asciicast" {
				lines := strings.SplitN(strings.TrimSpace(content), "\n", 2)
				var header struct {
					Version int `json:"version"`
				}
				if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
					t.Errorf("cast header not valid json: %v (line=%q)", err, lines[0])
				} else if header.Version != 2 {
					t.Errorf("cast header version = %d, want 2", header.Version)
				}
			}
		})
	}
}

// TestScreenRecordingPathTraversalE2E is the end-to-end regression test for
// the recorddir path-traversal fix: it drives real SSH sessions with
// malicious, path-traversal-attempting usernames through the actual
// sshpiperd binary with --username-as-recorddir enabled, and asserts that
// no file or directory is ever created outside of the configured recording
// root as a result.
func TestScreenRecordingPathTraversalE2E(t *testing.T) {
	upstream := createFakeEchoSshServer(t)

	recordParent := t.TempDir()
	recordDir := filepath.Join(recordParent, "records")
	if err := os.MkdirAll(recordDir, 0o700); err != nil {
		t.Fatalf("mkdir recordDir: %v", err)
	}

	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p", piperport,
		"--screen-recording-dir", recordDir,
		"--screen-recording-format", "asciicast",
		"--username-as-recorddir",
		"/sshpiperd/plugins/fixed",
		"--target", upstream.Addr().String(),
	)
	if err != nil {
		t.Fatalf("failed to run sshpiperd: %v", err)
	}
	t.Cleanup(func() { killCmd(piper) })
	waitForEndpointReady(piperaddr)

	for _, user := range []string{"../evil", "..", "../../outside"} {
		recordingSession(t, piperaddr, user, "should-not-be-recorded")
	}

	// Give the daemon time to react (mkdir attempt / rejection) after each
	// session tears down.
	time.Sleep(time.Second)

	parentEntries, err := os.ReadDir(recordParent)
	if err != nil {
		t.Fatalf("read record parent dir: %v", err)
	}
	if len(parentEntries) != 1 || parentEntries[0].Name() != filepath.Base(recordDir) {
		names := make([]string, 0, len(parentEntries))
		for _, e := range parentEntries {
			names = append(names, e.Name())
		}
		t.Fatalf("unexpected entries escaped into parent of recordDir: %v", names)
	}

	rootEntries, err := os.ReadDir(recordDir)
	if err != nil {
		t.Fatalf("read recordDir: %v", err)
	}
	if len(rootEntries) != 0 {
		names := make([]string, 0, len(rootEntries))
		for _, e := range rootEntries {
			names = append(names, e.Name())
		}
		t.Fatalf("recordDir should remain empty, found: %v", names)
	}
}
