//go:build full || e2e

package main

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

type fakeMeta struct {
	user, addr, id string
	meta           map[string]string
}

func (f fakeMeta) User() string              { return f.user }
func (f fakeMeta) RemoteAddr() string        { return f.addr }
func (f fakeMeta) UniqueID() string          { return f.id }
func (f fakeMeta) GetMeta(key string) string { return f.meta[key] }

var _ libplugin.ConnMetadata = fakeMeta{}

// TestRegisterAndForward drives the full protocol in process: it acts as the
// registrar's ssh client, completes a tcpip-forward, then acts as sshpiperd's
// connect path by calling the plugin callbacks directly and verifying that
// the resulting net.Conn pipes bytes through the registrar's
// forwarded-tcpip channel.
func TestRegisterAndForward(t *testing.T) {
	reg := newRegistry(newMemoryStore())
	srv, err := newRegisterServer(reg, "")
	if err != nil {
		t.Fatalf("newRegisterServer: %v", err)
	}
	cfg := buildPluginConfig(reg, srv)

	// Generate a fake downstream public key (ed25519) for the registrar.
	fakeDownstreamKey := []byte{0, 0, 0, 11, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9', 0, 0, 0, 32}
	fakeDownstreamKey = append(fakeDownstreamKey, make([]byte, 32)...) // 32-byte ed25519 public key

	// 1) Plugin assigns a register-side Uri via PublicKeyCallback.
	upstream, err := cfg.PublicKeyCallback(fakeMeta{user: "alice"}, fakeDownstreamKey)
	if err != nil {
		t.Fatalf("PublicKeyCallback(register): %v", err)
	}
	t.Logf("step 1: PublicKeyCallback(register) ok uri=%s", upstream.Uri)

	// 2) sshpiperd would now dial the upstream — emulate that via CreateConn.
	upConn, err := cfg.CreateConnCallback(upstream.Uri)
	if err != nil {
		t.Fatalf("CreateConnCallback(register): %v", err)
	}

	// 3) Act as the registrar's ssh.Client over that conn.
	clientCfg := &ssh.ClientConfig{
		User:            "alice",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	cc, chans, reqs, err := ssh.NewClientConn(upConn, "revtunnel-test", clientCfg)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	t.Logf("step 3: NewClientConn ok")
	client := ssh.NewClient(cc, chans, reqs)
	defer client.Close()

	// Open the session BEFORE issuing tcpip-forward so the server has somewhere
	// to write the registration block to.
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()
	t.Logf("step 4: NewSession ok")
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}
	t.Logf("step 5: Shell ok")

	// Capture forwarded-tcpip channels the server will open back at us.
	forwarded := client.HandleChannelOpen("forwarded-tcpip")

	// 6) Send tcpip-forward.
	type fwd struct {
		BindAddr string
		BindPort uint32
	}
	ok, reply, err := client.SendRequest("tcpip-forward", true, ssh.Marshal(fwd{"0.0.0.0", 0}))
	if err != nil || !ok {
		t.Fatalf("tcpip-forward: ok=%v reply=%v err=%v", ok, reply, err)
	}
	t.Logf("step 6: tcpip-forward ok reply=%x", reply)

	// 5) Read GUID from the session output.
	guid := readGuid(t, stdout, 5*time.Second)
	if guid == "" {
		t.Fatalf("no GUID in registration output")
	}

	rec, _, ok := reg.Lookup(guid)
	if !ok {
		t.Fatalf("registry missing guid %q", guid)
	}
	if rec.TargetUser != "alice" {
		t.Fatalf("target user mismatch: got %q", rec.TargetUser)
	}

	// 6) Plugin connect-side: validate pubkey then open the tunnel.
	// The stored DownstreamKeyWire must match what was sent during registration.
	if !bytes.Equal(rec.DownstreamKeyWire, fakeDownstreamKey) {
		t.Fatalf("DownstreamKeyWire not stored correctly")
	}
	up2, err := cfg.PublicKeyCallback(fakeMeta{user: guid}, fakeDownstreamKey)
	if err != nil {
		t.Fatalf("PublicKeyCallback(connect): %v", err)
	}
	if up2.UserName != "alice" {
		t.Fatalf("connect UserName=%q want alice", up2.UserName)
	}
	// 7) On the registrar side, accept forwarded-tcpip channels asynchronously
	// and echo bytes. Must be running before we call CreateConnCallback
	// (the server-side OpenChannel blocks until we Accept).
	acceptErr := make(chan error, 1)
	go func() {
		for nc := range forwarded {
			ch, fReqs, err := nc.Accept()
			if err != nil {
				acceptErr <- err
				return
			}
			go ssh.DiscardRequests(fReqs)
			go func(c ssh.Channel) {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}(ch)
		}
	}()

	tunnelConn, err := cfg.CreateConnCallback(up2.Uri)
	if err != nil {
		t.Fatalf("CreateConnCallback(connect): %v", err)
	}
	defer tunnelConn.Close()
	t.Logf("step 7: tunnel conn opened")

	// 8) Echo round-trip through the tunnel conn proves the pipe works.
	if _, err := tunnelConn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(tunnelConn, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo mismatch: %q", buf)
	}
	t.Logf("step 8: echo ok")

	select {
	case err := <-acceptErr:
		t.Fatalf("forwarded-tcpip accept: %v", err)
	default:
	}

	// 9) Wrong pubkey must be rejected.
	bogus := make([]byte, len(fakeDownstreamKey))
	copy(bogus, fakeDownstreamKey)
	bogus[len(bogus)-1] ^= 0xff
	if _, err := cfg.PublicKeyCallback(fakeMeta{user: guid}, bogus); err == nil {
		t.Fatalf("PublicKeyCallback accepted wrong key")
	}

	// 10) Unknown guid must be rejected — treated as a registration.
	up3, err := cfg.PublicKeyCallback(fakeMeta{user: "no-such-guid"}, fakeDownstreamKey)
	if err != nil {
		t.Fatalf("PublicKeyCallback for unknown user should succeed (register path): %v", err)
	}
	if up3 == nil {
		t.Fatalf("expected upstream for register path")
	}
}

func readGuid(t *testing.T, r io.Reader, timeout time.Duration) string {
	t.Helper()
	ch := make(chan string, 1)
	go func() {
		s := bufio.NewScanner(r)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			// GUID is printed as a bare UUID on its own line.
			if isUUID(line) {
				ch <- line
				return
			}
		}
		ch <- ""
	}()
	select {
	case g := <-ch:
		return g
	case <-time.After(timeout):
		t.Fatalf("timed out reading GUID")
		return ""
	}
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
