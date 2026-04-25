package admin

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/tg123/sshpiper/libadmin"
	"google.golang.org/grpc"
)

// startTestServer spins up an admin gRPC server on a random local port and
// returns a connected client plus the registry it operates on.
func startTestServer(t *testing.T) (*libadmin.Client, *Registry) {
	t.Helper()
	reg := NewRegistry()
	srv := NewServer(reg, "test-id", "test-version", "127.0.0.1:0")
	gs := grpc.NewServer()
	srv.Register(gs)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() { gs.Stop() })

	cl, err := libadmin.NewClient(lis.Addr().String(), libadmin.DialOptions{Insecure: true})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = cl.Close() })
	return cl, reg
}

func TestServer_ServerInfoListKill(t *testing.T) {
	c, reg := startTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info, err := c.ServerInfo(ctx)
	if err != nil {
		t.Fatalf("ServerInfo: %v", err)
	}
	if info.GetId() != "test-id" || info.GetVersion() != "test-version" {
		t.Fatalf("unexpected info: %+v", info)
	}

	pipe := &fakePipe{}
	reg.Add(Session{ID: "sess-1", DownstreamUser: "u", StartedAt: time.Now()}, pipe)

	sess, err := c.ListSessions(ctx)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sess) != 1 || sess[0].GetId() != "sess-1" {
		t.Fatalf("unexpected sessions: %+v", sess)
	}

	killed, err := c.KillSession(ctx, "sess-1")
	if err != nil {
		t.Fatalf("KillSession: %v", err)
	}
	if !killed {
		t.Fatal("KillSession should have reported true")
	}
	if pipe.closed.Load() != 1 {
		t.Fatalf("close calls = %d", pipe.closed.Load())
	}

	// Unknown id → killed=false but no error
	killed, err = c.KillSession(ctx, "missing")
	if err != nil {
		t.Fatalf("KillSession(missing): %v", err)
	}
	if killed {
		t.Fatal("KillSession(missing) should return false")
	}
}

func TestServer_StreamSession(t *testing.T) {
	c, reg := startTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	bc := reg.Add(Session{ID: "s"}, &fakePipe{})
	bc.Publish(Frame{Kind: "header", ChannelID: 1, Width: 80, Height: 24, Env: map[string]string{"TERM": "xterm"}})

	stream, err := c.RPC().StreamSession(ctx, &libadmin.StreamSessionRequest{Id: "s"})
	if err != nil {
		t.Fatalf("StreamSession: %v", err)
	}

	// First frame should be the replayed header.
	frame, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv header: %v", err)
	}
	hdr := frame.GetHeader()
	if hdr == nil || hdr.GetWidth() != 80 || hdr.GetChannelId() != 1 {
		t.Fatalf("bad header frame: %+v", frame)
	}

	// Publish an output event and verify it arrives.
	go bc.Publish(Frame{Kind: "o", ChannelID: 1, Data: []byte("hello")})
	frame, err = stream.Recv()
	if err != nil {
		t.Fatalf("Recv event: %v", err)
	}
	ev := frame.GetEvent()
	if ev == nil || ev.GetKind() != "o" || string(ev.GetData()) != "hello" {
		t.Fatalf("bad event frame: %+v", frame)
	}
}
