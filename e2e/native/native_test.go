//go:build (windows || darwin) && e2e

package native_test

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

const waitTimeout = 15 * time.Second

type nativeSuite struct {
	daemon   string
	keyPath  string
	signer   ssh.Signer
	upstream string
	plugins  map[string]string
}

func testNativeE2E(t *testing.T, lifecycle func(*testing.T, *nativeSuite)) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(t.TempDir(), "executables with spaces")
	if err := os.Mkdir(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	daemon := filepath.Join(binDir, "sshpiperd"+suffix)
	scenarios := map[string]func(*testing.T, *nativeSuite){
		"fixed":           testFixed,
		"workingdir":      testWorkingdir,
		"yaml":            testYAML,
		"username-router": testUsernameRouter,
		"lua":             testLua,
		"failtoban":       testFailtoban,
		"metrics":         testMetrics,
		"revtunnel":       testRevtunnel,
	}
	var release struct {
		Builds []struct {
			Main   string
			Binary string
			Dir    string
			Goos   []string
			Tags   []string
		}
	}
	data, err := os.ReadFile(filepath.Join(root, ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &release); err != nil {
		t.Fatal(err)
	}
	plugins := make(map[string]string)
	var order []string
	// Select actual release entries, not every plugin in the source tree.
	for _, build := range release.Builds {
		if !strings.HasPrefix(build.Binary, "plugins/") || len(build.Goos) > 0 && !slices.Contains(build.Goos, runtime.GOOS) {
			continue
		}
		name := filepath.Base(build.Binary)
		if scenarios[name] == nil {
			t.Errorf("%s release plugin %q has no native E2E scenario", runtime.GOOS, name)
		}
		if _, exists := plugins[name]; exists {
			t.Errorf("duplicate %s release plugin %q", runtime.GOOS, name)
		}
		plugins[name] = filepath.Join(binDir, name+suffix)
		order = append(order, name)
	}
	for name := range scenarios {
		if _, ok := plugins[name]; !ok {
			t.Errorf("E2E scenario %q is not a %s release plugin", name, runtime.GOOS)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	buildBinary := func(dir, output, pkg string, tags []string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "go", "build", "-tags", strings.Join(tags, ","), "-o", output, pkg)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", pkg, err, output)
		}
	}
	buildBinary(filepath.Join(root, "cmd", "sshpiperd"), daemon, ".", nil)
	for _, build := range release.Builds {
		if strings.HasPrefix(build.Binary, "plugins/") && (len(build.Goos) == 0 || slices.Contains(build.Goos, runtime.GOOS)) {
			buildBinary(filepath.Join(root, build.Dir), plugins[filepath.Base(build.Binary)], build.Main, build.Tags)
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

	suite := &nativeSuite{daemon: daemon, keyPath: keyPath, signer: signer, upstream: composeUpstream(t), plugins: plugins}
	for _, name := range order {
		t.Run(name, func(t *testing.T) { scenarios[name](t, suite) })
	}

	if lifecycle != nil {
		t.Run("kill-daemon-kills-plugin", func(t *testing.T) { lifecycle(t, suite) })
	}
}

type daemonProcess struct {
	cmd         *exec.Cmd
	done        chan struct{}
	err         error
	logPath     string
	requestStop func() error
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
			if err := killDaemon(piper); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Errorf("kill daemon: %v", err)
			}
			select {
			case <-piper.done:
			case <-time.After(waitTimeout):
				t.Error("daemon cleanup timed out")
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
	if err := startDaemonProcess(piper); err != nil {
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
	return dialPiperAs(t, address, signer, "user", ssh.Password(password))
}

func dialPiperAs(t *testing.T, address string, signer ssh.Signer, user string, auth ssh.AuthMethod) (*ssh.Client, error) {
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
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()),
	})
	if err != nil {
		conn.Close()
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
		t.Fatal("SSHPIPERD_E2E_UPSTREAM is required; run e2e/windows/run.ps1 or e2e/macos/run.sh to start the Compose SSH server")
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
