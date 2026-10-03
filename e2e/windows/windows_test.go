//go:build windows && e2e

package windows_test

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
)

const waitTimeout = 15 * time.Second

func TestWindowsE2E(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(t.TempDir(), "executables with spaces")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	daemon := filepath.Join(binDir, "sshpiperd.exe")
	fixed := filepath.Join(binDir, "fixed.exe")
	for _, build := range []struct {
		dir    string
		output string
		pkg    string
	}{
		{filepath.Join(root, "cmd", "sshpiperd"), daemon, "."},
		{root, fixed, "./plugin/fixed"},
	} {
		cmd := exec.CommandContext(t.Context(), "go", "build", "-tags", "full", "-o", build.output, build.pkg)
		cmd.Dir = build.dir
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", build.output, err, output)
		}
	}

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(binDir, "host key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("fixed-plugin-ssh", func(t *testing.T) {
		upstream := composeUpstream(t)
		piper := startDaemon(t, daemon, keyPath, nil, fixed, "--target", upstream)
		address := piper.waitReady(t)

		t.Run("reject-wrong-password", func(t *testing.T) {
			_, err := dialPiper(t, address, signer, "wrong password")
			if err == nil || !strings.Contains(err.Error(), "unable to authenticate") {
				t.Fatalf("expected authentication failure, got %v", err)
			}
		})

		for _, status := range []int{0, 23, 0} {
			t.Run(fmt.Sprintf("exit-%d", status), func(t *testing.T) {
				client, err := dialPiper(t, address, signer, "pass")
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
	})

	t.Run("kill-daemon-kills-plugin", func(t *testing.T) {
		helper, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		pidFile := filepath.Join(t.TempDir(), "plugin.pid")
		piper := startDaemon(t, daemon, keyPath, []string{"SSHPIPER_WINDOWS_JOB_PID=" + pidFile},
			helper, "-test.run=^TestWindowsJobPlugin$")
		var handle windows.Handle
		waitFor(t, "plugin PID", func() bool {
			data, err := os.ReadFile(pidFile)
			if errors.Is(err, os.ErrNotExist) || (err == nil && len(data) == 0) {
				piper.checkRunning(t)
				return false
			}
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.ParseUint(string(data), 10, 32)
			if err != nil {
				t.Fatalf("parse plugin PID: %v", err)
			}
			handle, err = windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, uint32(pid))
			if err != nil {
				t.Fatalf("open plugin process: %v", err)
			}
			return true
		})
		t.Cleanup(func() {
			defer windows.CloseHandle(handle)
			state, err := windows.WaitForSingleObject(handle, 0)
			if err != nil {
				t.Errorf("query plugin process: %v", err)
				return
			}
			if state == uint32(windows.WAIT_TIMEOUT) {
				if err := windows.TerminateProcess(handle, 1); err != nil {
					t.Errorf("clean up plugin: %v", err)
				}
				if state, err := windows.WaitForSingleObject(handle, uint32(waitTimeout.Milliseconds())); err != nil || state != windows.WAIT_OBJECT_0 {
					t.Errorf("wait for plugin cleanup: state=%d, err=%v", state, err)
				}
			}
		})
		piper.waitReady(t)
		if state, err := windows.WaitForSingleObject(handle, 0); err != nil || state != uint32(windows.WAIT_TIMEOUT) {
			t.Fatalf("plugin is not running: state=%d, err=%v", state, err)
		}
		if err := piper.cmd.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-piper.done:
		case <-time.After(waitTimeout):
			t.Fatal("daemon did not exit after Kill")
		}
		// Wait on a retained handle, not a PID that Windows could reuse.
		if state, err := windows.WaitForSingleObject(handle, uint32(waitTimeout.Milliseconds())); err != nil || state != windows.WAIT_OBJECT_0 {
			t.Fatalf("plugin survived daemon termination: state=%d, err=%v", state, err)
		}
	})
}

// This subprocess deliberately survives stdio EOF, so closing the transport
// cannot make the job-object cleanup test pass without KILL_ON_JOB_CLOSE.
func TestWindowsJobPlugin(t *testing.T) {
	pidFile := os.Getenv("SSHPIPER_WINDOWS_JOB_PID")
	if pidFile == "" {
		t.Skip("subprocess helper")
	}
	plugin, err := libplugin.NewFromStdio(libplugin.SshPiperPluginConfig{
		PasswordCallback: func(libplugin.ConnMetadata, []byte) (*libplugin.Upstream, error) {
			return nil, errors.New("lifetime-test plugin does not authenticate")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	go func() {
		if err := plugin.Serve(); err != nil {
			fmt.Fprintf(os.Stderr, "plugin transport closed: %v\n", err)
		}
	}()
	time.Sleep(5 * time.Minute)
	t.Fatal("lifetime-test plugin was not terminated")
}

type daemonProcess struct {
	cmd     *exec.Cmd
	done    chan struct{}
	err     error
	logPath string
}

func startDaemon(t *testing.T, binary, key string, env []string, plugins ...string) *daemonProcess {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "daemon.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	args := append([]string{"--address", "127.0.0.1", "--port", "0", "--server-key", key, "--log-format", "json"}, plugins...)
	cmd := exec.Command(binary, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = log
	cmd.Stderr = log
	piper := &daemonProcess{cmd: cmd, done: make(chan struct{}), logPath: logPath}
	t.Cleanup(func() {
		if cmd.Process != nil {
			select {
			case <-piper.done:
			default:
				if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
					t.Errorf("kill daemon: %v", err)
				}
				select {
				case <-piper.done:
				case <-time.After(waitTimeout):
					t.Error("daemon cleanup timed out")
				}
			}
		}
		if err := log.Close(); err != nil {
			t.Errorf("close daemon log: %v", err)
		}
		if t.Failed() {
			data, err := os.ReadFile(logPath)
			if err != nil {
				t.Errorf("read daemon log: %v", err)
			} else {
				t.Logf("daemon output:\n%s", data)
			}
		}
	})
	if err := cmd.Start(); err != nil {
		t.Fatalf("start daemon: %v", err)
	}
	go func() {
		piper.err = cmd.Wait()
		close(piper.done)
	}()
	return piper
}

func (p *daemonProcess) checkRunning(t *testing.T) {
	t.Helper()
	select {
	case <-p.done:
		t.Fatalf("daemon exited before readiness: %v", p.err)
	default:
	}
}

func (p *daemonProcess) waitReady(t *testing.T) string {
	t.Helper()
	var address string
	waitFor(t, "daemon SSH readiness", func() bool {
		p.checkRunning(t)
		data, err := os.ReadFile(p.logPath)
		if err != nil {
			t.Fatal(err)
		}
		lines := bytes.Split(data, []byte("\n"))
		for _, line := range lines[:len(lines)-1] {
			var entry struct {
				Message string `json:"msg"`
				Address string `json:"address"`
			}
			if err := json.Unmarshal(line, &entry); err == nil && entry.Message == "sshpiperd is listening" {
				address = entry.Address
				return address != ""
			}
		}
		return false
	})
	return address
}

func waitFor(t *testing.T, description string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func dialPiper(t *testing.T, address string, signer ssh.Signer, password string) (*ssh.Client, error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, waitTimeout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatal(err)
	}
	c, channels, requests, err := ssh.NewClientConn(conn, address, &ssh.ClientConfig{
		User:            "user",
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()),
	})
	if err != nil {
		return nil, err
	}
	client := ssh.NewClient(c, channels, requests)
	t.Cleanup(func() { client.Close() })
	return client, nil
}

func composeUpstream(t *testing.T) string {
	t.Helper()
	address := os.Getenv("SSHPIPERD_E2E_UPSTREAM")
	if address == "" {
		t.Fatal("SSHPIPERD_E2E_UPSTREAM is required; run e2e\\windows\\run.ps1 to start the Compose SSH server")
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		t.Fatalf("invalid SSHPIPERD_E2E_UPSTREAM: %v", err)
	}
	waitFor(t, "Compose OpenSSH server at "+address, func() bool {
		conn, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			return false
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		banner, err := bufio.NewReader(conn).ReadString('\n')
		return err == nil && strings.HasPrefix(banner, "SSH-2.0-OpenSSH")
	})
	return address
}
