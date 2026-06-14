package connovergrpc

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func dialMsg(uri string) *Packet {
	return &Packet{Payload: &Packet_DialRequest{DialRequest: &DialRequest{Uri: uri}}}
}

func TestServeCreateConnTunnelsData(t *testing.T) {
	upstream, peer := net.Pipe()
	defer upstream.Close()
	defer peer.Close()

	in := make(chan *Packet, 8)
	out := make(chan *Packet, 8)
	stream := &pipePacketStream{in: in, out: out}

	var gotURI string
	done := make(chan error, 1)
	go func() {
		done <- ServeCreateConn(stream, func(uri string) (net.Conn, error) {
			gotURI = uri
			return upstream, nil
		})
	}()

	// first frame carries the DialRequest
	in <- dialMsg("tcp://upstream:22")
	// subsequent frames carry connection bytes from the peer side
	in <- &Packet{Payload: &Packet_Data{Data: []byte("ping")}}

	buf := make([]byte, 4)
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatalf("read from peer failed: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("peer got %q, want %q", buf, "ping")
	}

	// bytes from the upstream peer are tunneled back as data frames
	if _, err := peer.Write([]byte("pong")); err != nil {
		t.Fatalf("write to peer failed: %v", err)
	}
	if got := <-out; string(got.GetData()) != "pong" {
		t.Fatalf("tunneled data = %q, want %q", got.GetData(), "pong")
	}

	close(in)
	<-done

	if gotURI != "tcp://upstream:22" {
		t.Fatalf("create got uri %q, want %q", gotURI, "tcp://upstream:22")
	}
}

func TestServeCreateConnMissingRequest(t *testing.T) {
	s := &fakePacketStream{recv: []recvMsg{
		{msg: &Packet{Payload: &Packet_Data{Data: []byte("data")}}},
	}}

	err := ServeCreateConn(s, func(string) (net.Conn, error) {
		t.Fatal("create should not be called when the first frame is not a DialRequest")
		return nil, nil
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", err)
	}
}

func TestServeCreateConnRecvError(t *testing.T) {
	wantErr := errors.New("recv boom")
	s := &fakePacketStream{recv: []recvMsg{{err: wantErr}}}

	if err := ServeCreateConn(s, func(string) (net.Conn, error) { return nil, nil }); !errors.Is(err, wantErr) {
		t.Fatalf("ServeCreateConn error = %v, want %v", err, wantErr)
	}
}

func TestServeCreateConnNilCallback(t *testing.T) {
	s := &fakePacketStream{}
	err := ServeCreateConn(s, nil)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("ServeCreateConn error = %v, want Unimplemented", err)
	}
}

func TestServeCreateConnCreateError(t *testing.T) {
	wantErr := errors.New("create boom")
	s := &fakePacketStream{recv: []recvMsg{{msg: dialMsg("tcp://x:1")}}}

	err := ServeCreateConn(s, func(string) (net.Conn, error) {
		return nil, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("ServeCreateConn error = %v, want %v", err, wantErr)
	}
}

// fakeConnOverGrpcClient drives DialContext against an in-memory ServeCreateConn
// server, exercising the full client/server round-trip over the helpers.
type fakeConnOverGrpcClient struct {
	ConnOverGrpcClient
	create CreateConnFunc
}

func (c *fakeConnOverGrpcClient) CreateConn(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[Packet, Packet], error) {
	c2s := make(chan *Packet, 8)
	s2c := make(chan *Packet, 8)

	go func() {
		_ = ServeCreateConn(&pipePacketStream{in: c2s, out: s2c}, c.create)
		close(s2c)
	}()

	return &fakeBidiClient{in: s2c, out: c2s}, nil
}

func TestDialContextRoundTrip(t *testing.T) {
	upstream, peer := net.Pipe()
	defer peer.Close()

	client := &fakeConnOverGrpcClient{create: func(uri string) (net.Conn, error) {
		if uri != "tcp://upstream:22" {
			t.Errorf("server got uri %q, want %q", uri, "tcp://upstream:22")
		}
		return upstream, nil
	}}

	conn, err := DialContext(context.Background(), client, "tcp://upstream:22")
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()

	if got := conn.RemoteAddr().String(); got != "tcp://upstream:22" {
		t.Fatalf("RemoteAddr = %q, want %q", got, "tcp://upstream:22")
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("conn write failed: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatalf("peer read failed: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("peer got %q, want %q", buf, "ping")
	}

	if _, err := peer.Write([]byte("pong")); err != nil {
		t.Fatalf("peer write failed: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("conn read failed: %v", err)
	}
	if string(got) != "pong" {
		t.Fatalf("conn got %q, want %q", got, "pong")
	}
}

// fakeBidiClient is an in-memory grpc.BidiStreamingClient backed by channels.
type fakeBidiClient struct {
	grpc.ClientStream
	in  chan *Packet
	out chan *Packet
}

func (c *fakeBidiClient) Send(m *Packet) error {
	c.out <- m
	return nil
}

func (c *fakeBidiClient) Recv() (*Packet, error) {
	m, ok := <-c.in
	if !ok {
		return nil, io.EOF
	}
	return m, nil
}

func (c *fakeBidiClient) CloseSend() error { return nil }

func TestNewServerCreateConn(t *testing.T) {
	upstream, peer := net.Pipe()
	defer upstream.Close()
	defer peer.Close()

	in := make(chan *Packet, 8)
	out := make(chan *Packet, 8)

	srv := NewServer(func(string) (net.Conn, error) { return upstream, nil })

	done := make(chan error, 1)
	go func() {
		done <- srv.CreateConn(&pipeServerStream{pipePacketStream{in: in, out: out}})
	}()

	in <- dialMsg("req")
	in <- &Packet{Payload: &Packet_Data{Data: []byte("ping")}}

	buf := make([]byte, 4)
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatalf("peer read failed: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("peer got %q, want %q", buf, "ping")
	}

	close(in)
	<-done
}

// errBidiClient is a ConnOverGrpcClient that fails to open the stream.
type errBidiClient struct {
	ConnOverGrpcClient
	err error
}

func (c *errBidiClient) CreateConn(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[Packet, Packet], error) {
	return nil, c.err
}

func TestDialContextCreateConnError(t *testing.T) {
	wantErr := errors.New("open boom")
	if _, err := DialContext(context.Background(), &errBidiClient{err: wantErr}, ""); !errors.Is(err, wantErr) {
		t.Fatalf("DialContext error = %v, want %v", err, wantErr)
	}
}

// sendErrClient returns a stream whose first Send fails.
type sendErrClient struct {
	ConnOverGrpcClient
	err error
}

type sendErrStream struct {
	grpc.ClientStream
	err error
}

func (s *sendErrStream) Send(*Packet) error     { return s.err }
func (s *sendErrStream) Recv() (*Packet, error) { return nil, io.EOF }

func (c *sendErrClient) CreateConn(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[Packet, Packet], error) {
	return &sendErrStream{err: c.err}, nil
}

func TestDialContextSendError(t *testing.T) {
	wantErr := errors.New("send boom")
	if _, err := DialContext(context.Background(), &sendErrClient{err: wantErr}, ""); !errors.Is(err, wantErr) {
		t.Fatalf("DialContext error = %v, want %v", err, wantErr)
	}
}

// pipeServerStream adapts pipePacketStream into a grpc BidiStreamingServer.
type pipeServerStream struct {
	pipePacketStream
}

func (p *pipeServerStream) SetHeader(metadata.MD) error  { return nil }
func (p *pipeServerStream) SendHeader(metadata.MD) error { return nil }
func (p *pipeServerStream) SetTrailer(metadata.MD)       {}
func (p *pipeServerStream) Context() context.Context     { return context.Background() }
func (p *pipeServerStream) SendMsg(m any) error          { return nil }
func (p *pipeServerStream) RecvMsg(m any) error          { return nil }
