//go:build windows && e2e

package windows_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func (s *windowsSuite) start(t *testing.T, plugins ...string) *daemonProcess {
	t.Helper()
	return startDaemon(t, s.daemon, s.keyPath, nil, plugins...)
}

func writeFixture(t *testing.T, filename, content string) {
	t.Helper()
	if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func requireAuthenticationFailure(t *testing.T, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "unable to authenticate") {
		t.Fatalf("expected authentication failure, got %v", err)
	}
}

func runWhoami(t *testing.T, client *ssh.Client) {
	t.Helper()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	output, err := session.CombinedOutput("whoami")
	if err != nil {
		t.Fatalf("whoami: %v\n%s", err, output)
	}
	if string(output) != "user\n" {
		t.Fatalf("upstream user = %q, want user", output)
	}
}

func (s *windowsSuite) route(t *testing.T, address, user string) *ssh.Client {
	t.Helper()
	client, err := dialPiperAs(t, address, s.signer, user, ssh.Password("pass"))
	if err != nil {
		t.Fatal(err)
	}
	runWhoami(t, client)
	return client
}

func testFixed(t *testing.T, s *windowsSuite) {
	piper := s.start(t, s.plugins["fixed"], "--target", s.upstream)
	address := piper.waitReady(t)
	t.Run("reject-wrong-password", func(t *testing.T) {
		_, err := dialPiper(t, address, s.signer, "wrong password")
		requireAuthenticationFailure(t, err)
	})
	for _, status := range []int{0, 23, 0} {
		t.Run(fmt.Sprintf("exit-%d", status), func(t *testing.T) {
			client, err := dialPiper(t, address, s.signer, "pass")
			if err != nil {
				t.Fatal(err)
			}
			session, err := client.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			payload := strings.Repeat("Windows SSH payload\r\n\x00", 1024)
			session.Stdin = strings.NewReader(payload)
			var stdout, stderr bytes.Buffer
			session.Stdout = &stdout
			session.Stderr = &stderr
			err = session.Run(fmt.Sprintf("cat; printf 'windows stderr\\r\\n' >&2; exit %d", status))
			if status == 0 {
				if err != nil {
					t.Fatalf("exec: %v", err)
				}
			} else {
				var exitErr *ssh.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitStatus() != status {
					t.Fatalf("expected exit status %d, got %v", status, err)
				}
			}
			if stdout.String() != payload {
				t.Fatalf("stdin/stdout round trip mismatch: got %d bytes, want %d", stdout.Len(), len(payload))
			}
			if stderr.String() != "windows stderr\r\n" {
				t.Fatalf("stderr = %q", stderr.String())
			}
		})
	}
}

func testWorkingdir(t *testing.T, s *windowsSuite) {
	root := filepath.Join(t.TempDir(), "working directory")
	userDir := filepath.Join(root, "alias")
	if err := os.MkdirAll(userDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(userDir, "sshpiper_upstream"), "# Windows alias\nuser@"+s.upstream+"\n")
	// Windows mode bits cannot express the plugin's Unix owner-only check.
	piper := s.start(t, s.plugins["workingdir"], "--root", root, "--no-check-perm")
	address := piper.waitReady(t)
	s.route(t, address, "alias")
	_, err := dialPiperAs(t, address, s.signer, "missing", ssh.Password("pass"))
	requireAuthenticationFailure(t, err)
}

func testYAML(t *testing.T, s *windowsSuite) {
	config := filepath.Join(t.TempDir(), "routing rules.yaml")
	writeFixture(t, config, fmt.Sprintf(`version: "1.0"
pipes:
- from:
    - username: "^windows_(.*)$"
      username_regex_match: true
  to:
    host: %q
    username: "$1"
`, s.upstream))
	piper := s.start(t, s.plugins["yaml"], "--config", config, "--no-check-perm")
	address := piper.waitReady(t)
	s.route(t, address, "windows_user")
	_, err := dialPiperAs(t, address, s.signer, "unmatched", ssh.Password("pass"))
	requireAuthenticationFailure(t, err)
}

func testUsernameRouter(t *testing.T, s *windowsSuite) {
	piper := s.start(t, s.plugins["username-router"])
	address := piper.waitReady(t)
	s.route(t, address, s.upstream+"+user")
	_, err := dialPiperAs(t, address, s.signer, "no-target-separator", ssh.Password("pass"))
	requireAuthenticationFailure(t, err)
}

func testLua(t *testing.T, s *windowsSuite) {
	script := filepath.Join(t.TempDir(), "routing script.lua")
	writeFixture(t, script, fmt.Sprintf(`function sshpiper_on_password(conn, password)
    if conn.sshpiper_user ~= "lua_alias" then
        return nil
    end
    return { host = %q, username = "user", password = password }
end
`, s.upstream))
	piper := s.start(t, s.plugins["lua"], "--script", script)
	address := piper.waitReady(t)
	s.route(t, address, "lua_alias")
	_, err := dialPiperAs(t, address, s.signer, "rejected", ssh.Password("pass"))
	requireAuthenticationFailure(t, err)
}

func testFailtoban(t *testing.T, s *windowsSuite) {
	for _, ignored := range []bool{false, true} {
		t.Run(fmt.Sprintf("ignore-loopback-%t", ignored), func(t *testing.T) {
			args := []string{
				s.plugins["fixed"], "--target", s.upstream, "--",
				s.plugins["failtoban"], "--max-failures", "1",
			}
			if ignored {
				args = append(args, "--ignore-ip", "127.0.0.1")
			}
			piper := s.start(t, args...)
			address := piper.waitReady(t)
			s.route(t, address, "user").Close()
			_, err := dialPiper(t, address, s.signer, "wrong password")
			requireAuthenticationFailure(t, err)
			if ignored {
				s.route(t, address, "user")
				return
			}
			_, err = dialPiper(t, address, s.signer, "pass")
			if err == nil {
				t.Fatal("failtoban accepted a banned client with valid credentials")
			}
			piper.checkRunning(t)
			waitFor(t, "failtoban rejection", func() bool {
				log, err := os.ReadFile(piper.logPath)
				if err != nil {
					t.Fatal(err)
				}
				return bytes.Contains(log, []byte("failtoban: ip 127.0.0.1 too auth many failures"))
			})
		})
	}
}

func testMetrics(t *testing.T, s *windowsSuite) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	metricsAddress := listener.Addr().String()
	_, port, err := net.SplitHostPort(metricsAddress)
	if err != nil {
		t.Fatal(err)
	}
	// The metrics plugin does not report its allocated port when given port 0.
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	piper := s.start(t, s.plugins["fixed"], "--target", s.upstream, "--",
		s.plugins["metrics"], "--address", "127.0.0.1", "--port", port,
		"--collect-pipe-create-errors", "--collect-upstream-auth-failures")
	address := piper.waitReady(t)
	httpClient := &http.Client{Timeout: time.Second}
	t.Cleanup(httpClient.CloseIdleConnections)
	scrape := func() string {
		t.Helper()
		piper.checkRunning(t)
		response, err := httpClient.Get("http://" + metricsAddress + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("metrics HTTP status %s: %s", response.Status, body)
		}
		return string(body)
	}
	waitFor(t, "metrics HTTP readiness", func() bool {
		piper.checkRunning(t)
		response, err := httpClient.Get("http://" + metricsAddress + "/metrics")
		if err != nil {
			return false
		}
		response.Body.Close()
		return response.StatusCode == http.StatusOK
	})
	client := s.route(t, address, "user")
	gauge := fmt.Sprintf("sshpiper_pipe_open_connections{remote_addr=%q,username=\"user\"}", client.LocalAddr().String())
	waitFor(t, "open connection gauge", func() bool {
		return strings.Contains(scrape(), gauge+" 1\n")
	})
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "closed connection gauge removal", func() bool {
		return !strings.Contains(scrape(), gauge)
	})
	_, err = dialPiper(t, address, s.signer, "wrong password")
	requireAuthenticationFailure(t, err)
	waitFor(t, "authentication and pipe creation error counters", func() bool {
		body := scrape()
		return regexp.MustCompile(`(?m)^sshpiper_upstream_auth_failures\{method="password",remote_addr="[^"]+",user="user"\} [1-9][0-9]*\n`).MatchString(body) &&
			regexp.MustCompile(`(?m)^sshpiper_pipe_create_errors\{remote_addr="[^"]+"\} [1-9][0-9]*\n`).MatchString(body)
	})
}

func testRevtunnel(t *testing.T, s *windowsSuite) {
	store := filepath.Join(t.TempDir(), "tunnel sessions")
	storeURI := (&url.URL{Scheme: "file", Path: "/" + filepath.ToSlash(store)}).String()
	piper := s.start(t, s.plugins["revtunnel"], "--session-store", storeURI)
	address := piper.waitReady(t)
	registrar, err := dialPiperAs(t, address, s.signer, "user", ssh.PublicKeys(s.signer))
	if err != nil {
		t.Fatal(err)
	}
	session, err := registrar.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Setenv("ALLOWPASSWORD", "1"); err != nil {
		t.Fatal(err)
	}
	if err := session.Shell(); err != nil {
		t.Fatal(err)
	}
	forwarded := registrar.HandleChannelOpen("forwarded-tcpip")
	request := struct {
		BindAddr string
		BindPort uint32
	}{"127.0.0.1", 0}
	ok, reply, err := registrar.SendRequest("tcpip-forward", true, ssh.Marshal(request))
	if err != nil || !ok {
		t.Fatalf("register reverse forward: ok=%t, err=%v", ok, err)
	}
	var allocated struct{ Port uint32 }
	if err := ssh.Unmarshal(reply, &allocated); err != nil || allocated.Port == 0 {
		t.Fatalf("invalid allocated port: reply=%x, err=%v", reply, err)
	}
	var guid string
	scanner := bufio.NewScanner(stdout)
	guidPattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	for scanner.Scan() {
		if guidPattern.MatchString(scanner.Text()) {
			guid = scanner.Text()
			break
		}
	}
	if guid == "" {
		t.Fatalf("no tunnel GUID in registration: %v", scanner.Err())
	}
	recordPath := filepath.Join(store, guid+".json")
	record, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("read Windows file session store: %v", err)
	}
	var saved struct {
		AllowPassword bool   `json:"allow_password"`
		TargetUser    string `json:"target_user"`
	}
	if err := json.Unmarshal(record, &saved); err != nil {
		t.Fatal(err)
	}
	if !saved.AllowPassword || saved.TargetUser != "user" {
		t.Fatalf("password forwarding and target user not persisted: %s", record)
	}
	// Relay the actual reverse-forward channel to the existing Compose sshd.
	relayDone := make(chan error, 1)
	go func() {
		incoming, ok := <-forwarded
		if !ok {
			relayDone <- io.EOF
			return
		}
		channel, requests, err := incoming.Accept()
		if err != nil {
			relayDone <- err
			return
		}
		defer channel.Close()
		go ssh.DiscardRequests(requests)
		upstream, err := net.DialTimeout("tcp", s.upstream, waitTimeout)
		if err != nil {
			relayDone <- err
			return
		}
		defer upstream.Close()
		if err := upstream.SetDeadline(time.Now().Add(waitTimeout)); err != nil {
			relayDone <- err
			return
		}
		copied := make(chan error, 1)
		go func() {
			_, err := io.Copy(upstream, channel)
			copied <- errors.Join(err, upstream.(*net.TCPConn).CloseWrite())
		}()
		_, err = io.Copy(channel, upstream)
		channel.Close()
		upstream.Close()
		copyErr := <-copied
		relayDone <- errors.Join(err, copyErr)
	}()
	t.Cleanup(func() {
		registrar.Close()
		select {
		case err := <-relayDone:
			if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
				t.Errorf("reverse tunnel relay: %v", err)
			}
		case <-time.After(waitTimeout):
			t.Error("reverse tunnel relay did not stop")
		}
	})
	connector := s.route(t, address, guid)
	if err := connector.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "revoked tunnel file removal", func() bool {
		_, err := os.Stat(recordPath)
		if errors.Is(err, os.ErrNotExist) {
			return true
		}
		if err != nil {
			t.Fatal(err)
		}
		return false
	})
	_, err = dialPiperAs(t, address, s.signer, guid, ssh.Password("pass"))
	requireAuthenticationFailure(t, err)
	piper.checkRunning(t)
}
