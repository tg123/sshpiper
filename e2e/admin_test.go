package e2e_test

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tg123/sshpiper/libadmin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestAdminGRPC_InsecureLifecycle exercises the sshpiperd admin gRPC API
// end-to-end against a real piper + real upstream SSH server:
//
//   - sshpiperd is started with `--admin-grpc-port` + `--admin-grpc-insecure`
//     and a fixed plugin pointing at the host-password upstream.
//   - libadmin.Client connects insecurely to the admin endpoint and checks
//     ServerInfo / empty ListSessions.
//   - A real SSH session is opened through the piper; admin ListSessions
//     must observe the live session with the correct downstream user/addr.
//   - KillSession is invoked and the SSH client is expected to be torn down,
//     after which ListSessions must report no live sessions.
func TestAdminGRPC_InsecureLifecycle(t *testing.T) {
	piperaddr, piperport := nextAvailablePiperAddress()
	adminPort := strconv.Itoa(nextAvailablePort())
	adminAddr := "127.0.0.1:" + adminPort

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p", piperport,
		"--admin-grpc-address", "127.0.0.1",
		"--admin-grpc-port", adminPort,
		"--admin-grpc-id", "e2e-piper",
		"--admin-grpc-insecure",
		"/sshpiperd/plugins/fixed",
		"--target", "host-password:2222",
	)
	if err != nil {
		t.Fatalf("failed to run sshpiperd: %v", err)
	}
	defer killCmd(piper)

	waitForEndpointReady(piperaddr)
	waitForEndpointReady(adminAddr)

	client, err := libadmin.NewClient(adminAddr, libadmin.DialOptions{Insecure: true})
	if err != nil {
		t.Fatalf("failed to dial admin gRPC: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// ServerInfo should reflect the --admin-grpc-id we passed and a non-empty
	// ssh listening address.
	info, err := client.ServerInfo(ctx)
	if err != nil {
		t.Fatalf("ServerInfo: %v", err)
	}
	if info.GetId() != "e2e-piper" {
		t.Errorf("ServerInfo.Id = %q, want %q", info.GetId(), "e2e-piper")
	}
	if info.GetSshAddr() == "" {
		t.Errorf("ServerInfo.SshAddr is empty")
	}
	if info.GetStartedAt() == 0 {
		t.Errorf("ServerInfo.StartedAt is zero")
	}

	// No sessions yet.
	sessions, err := client.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions(empty): %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions before ssh, got %d", len(sessions))
	}

	// Start a real SSH session through the piper that will keep stdin open.
	// Snapshot existing session IDs so we can identify "our" new session
	// by diff regardless of downstream username (the upstream sshd only
	// accepts a fixed user, and other tests sharing this binary may also
	// have sessions in flight).
	preexisting := make(map[string]struct{}, len(sessions))
	for _, s := range sessions {
		preexisting[s.GetId()] = struct{}{}
	}

	targetfile := uuid.New().String()
	sshCmd, stdin, stdout, err := runCmd(
		"ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "RequestTTY=yes",
		"-p", piperport,
		"-l", "user",
		"127.0.0.1",
		fmt.Sprintf(`sh -c "echo SSHREADY && cat > /shared/%v"`, targetfile),
	)
	if err != nil {
		t.Fatalf("failed to start ssh: %v", err)
	}
	defer killCmd(sshCmd)
	enterPassword(stdin, stdout, "pass")
	waitForStdoutContains(stdout, "SSHREADY", func(_ string) {})

	// Wait for the admin registry to observe the new session.
	var live *libadmin.Session
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		sessions, err = client.ListSessions(ctx)
		if err != nil {
			t.Fatalf("ListSessions(live): %v", err)
		}
		for _, s := range sessions {
			if _, seen := preexisting[s.GetId()]; seen {
				continue
			}
			if s.GetDownstreamUser() == "user" {
				live = s
				break
			}
		}
		if live != nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if live == nil {
		t.Fatalf("admin ListSessions did not report the live ssh session")
	}
	if live.GetId() == "" {
		t.Errorf("Session.Id is empty")
	}
	if !strings.Contains(live.GetDownstreamAddr(), "127.0.0.1") {
		t.Errorf("Session.DownstreamAddr = %q, want it to contain 127.0.0.1", live.GetDownstreamAddr())
	}
	if live.GetUpstreamAddr() == "" {
		t.Errorf("Session.UpstreamAddr is empty")
	}
	if live.GetStartedAt() == 0 {
		t.Errorf("Session.StartedAt is zero")
	}

	// Open a StreamSession against the live session and verify that frames
	// captured from the upstream actually flow through the admin gRPC
	// stream. Replay=true so we are guaranteed at least the cached header
	// frame even if no new output arrives in time.
	streamCtx, streamCancel := context.WithCancel(ctx)
	defer streamCancel()
	stream, err := client.RPC().StreamSession(streamCtx, &libadmin.StreamSessionRequest{
		Id:     live.GetId(),
		Replay: true,
	})
	if err != nil {
		t.Fatalf("StreamSession: %v", err)
	}

	type recvResult struct {
		gotHeader bool
		gotProbe  bool
		err       error
	}
	probe := "STREAMPROBE-" + uuid.New().String()
	results := make(chan recvResult, 1)
	go func() {
		var res recvResult
		var output []byte
		for {
			frame, err := stream.Recv()
			if err != nil {
				res.err = err
				results <- res
				return
			}
			if frame.GetHeader() != nil {
				res.gotHeader = true
			}
			if ev := frame.GetEvent(); ev != nil && ev.GetKind() == "o" {
				output = append(output, ev.GetData()...)
				if strings.Contains(string(output), probe) {
					res.gotProbe = true
					results <- res
					return
				}
			}
		}
	}()

	// Write the probe through ssh stdin; with RequestTTY=yes the upstream
	// PTY echoes the bytes back, which streamhook captures as "o" frames.
	if _, err := stdin.Write([]byte(probe + "\n")); err != nil {
		t.Fatalf("write probe to ssh stdin: %v", err)
	}

	select {
	case res := <-results:
		if !res.gotProbe {
			t.Fatalf("StreamSession did not deliver probe %q before stream ended (err=%v, gotHeader=%v)", probe, res.err, res.gotHeader)
		}
		if !res.gotHeader {
			t.Errorf("StreamSession did not deliver any header frame (replay=true)")
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("StreamSession did not deliver probe %q within timeout", probe)
	}
	streamCancel()

	// KillSession should report killed=true.
	killed, err := client.KillSession(ctx, live.GetId())
	if err != nil {
		t.Fatalf("KillSession: %v", err)
	}
	if !killed {
		t.Fatalf("KillSession returned killed=false for live id %q", live.GetId())
	}

	// Wait for the ssh client to actually exit (its connection was torn down).
	exited := make(chan error, 1)
	go func() { exited <- sshCmd.Wait() }()
	select {
	case <-exited:
	case <-time.After(15 * time.Second):
		t.Fatal("ssh client did not exit after KillSession")
	}

	// And the admin registry should have unregistered the session.
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		sessions, err = client.ListSessions(ctx)
		if err != nil {
			t.Fatalf("ListSessions(after kill): %v", err)
		}
		stillThere := false
		for _, s := range sessions {
			if s.GetId() == live.GetId() {
				stillThere = true
				break
			}
		}
		if !stillThere {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	for _, s := range sessions {
		if s.GetId() == live.GetId() {
			t.Fatalf("admin still reports session %q after KillSession", live.GetId())
		}
	}

	// StreamSession against a non-existent / already-gone session id must
	// surface a NotFound gRPC error to the client, not Unknown.
	bogusStream, err := client.RPC().StreamSession(ctx, &libadmin.StreamSessionRequest{Id: live.GetId()})
	if err != nil {
		t.Fatalf("opening stream for missing session: %v", err)
	}
	if _, err := bogusStream.Recv(); err == nil {
		t.Fatalf("StreamSession against killed session id unexpectedly succeeded")
	} else if got := status.Code(err); got != codes.NotFound {
		t.Fatalf("StreamSession against killed session: got code=%s err=%v, want NotFound", got, err)
	}
}

// TestAdminGRPC_RequiresTLSWithoutInsecureFlag verifies that starting
// sshpiperd with --admin-grpc-port but neither TLS material nor
// --admin-grpc-insecure is rejected at startup.
func TestAdminGRPC_RequiresTLSWithoutInsecureFlag(t *testing.T) {
	_, piperport := nextAvailablePiperAddress()
	adminPort := strconv.Itoa(nextAvailablePort())

	c, _, stdout, err := runCmd("/sshpiperd/sshpiperd",
		"-p", piperport,
		"--admin-grpc-address", "127.0.0.1",
		"--admin-grpc-port", adminPort,
		"/sshpiperd/plugins/fixed",
		"--target", "host-password:2222",
	)
	if err != nil {
		t.Fatalf("failed to start sshpiperd: %v", err)
	}
	defer killCmd(c)

	waitForStdoutContains(stdout, "admin gRPC API requires", func(line string) {
		t.Logf("got expected startup error: %s", line)
	})
}
