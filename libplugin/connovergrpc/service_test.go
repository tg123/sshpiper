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

func requestMsg(b string) *ConnMessage {
	return &ConnMessage{Message: &ConnMessage_Request{Request: []byte(b)}}
}

func TestServeCreateConnTunnelsData(t *testing.T) {
	upstream, peer := net.Pipe()
	defer upstream.Close()
	defer peer.Close()

	in := make(chan *ConnMessage, 8)
	out := make(chan *ConnMessage, 8)
	stream := &pipeMessageStream{in: in, out: out}

	var gotRequest []byte
	done := make(chan error, 1)
	go func() {
		done <- ServeCreateConn(stream, func(request []byte) (net.Conn, error) {
			gotRequest = request
			return upstream, nil
		})
	}()

	// first frame carries the opaque request
	in <- requestMsg("hello-request")
	// subsequent frames carry connection bytes from the peer side
	in <- &ConnMessage{Message: &ConnMessage_Data{Data: []byte("ping")}}

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

	if string(gotRequest) != "hello-request" {
		t.Fatalf("create got request %q, want %q", gotRequest, "hello-request")
	}
}

func TestServeCreateConnMissingRequest(t *testing.T) {
	s := &fakeMessageStream{recv: []recvMsg{
		{msg: &ConnMessage{Message: &ConnMessage_Data{Data: []byte("data")}}},
	}}

	err := ServeCreateConn(s, func([]byte) (net.Conn, error) {
		t.Fatal("create should not be called when the first frame is not a request")
		return nil, nil
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected invalid argument, got %v", err)
	}
}

func TestServeCreateConnRecvError(t *testing.T) {
	wantErr := errors.New("recv boom")
	s := &fakeMessageStream{recv: []recvMsg{{err: wantErr}}}

	if err := ServeCreateConn(s, nil); !errors.Is(err, wantErr) {
		t.Fatalf("ServeCreateConn error = %v, want %v", err, wantErr)
	}
}

func TestServeCreateConnCreateError(t *testing.T) {
	wantErr := errors.New("create boom")
	s := &fakeMessageStream{recv: []recvMsg{{msg: requestMsg("req")}}}

	err := ServeCreateConn(s, func([]byte) (net.Conn, error) {
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

func (c *fakeConnOverGrpcClient) CreateConn(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[ConnMessage, ConnMessage], error) {
	c2s := make(chan *ConnMessage, 8)
	s2c := make(chan *ConnMessage, 8)

	go func() {
		_ = ServeCreateConn(&pipeMessageStream{in: c2s, out: s2c}, c.create)
		close(s2c)
	}()

	return &fakeBidiClient{in: s2c, out: c2s}, nil
}

func TestDialContextRoundTrip(t *testing.T) {
	upstream, peer := net.Pipe()
	defer peer.Close()

	client := &fakeConnOverGrpcClient{create: func(request []byte) (net.Conn, error) {
		if string(request) != "req-bytes" {
			t.Errorf("server got request %q, want %q", request, "req-bytes")
		}
		return upstream, nil
	}}

	conn, err := DialContext(context.Background(), client, []byte("req-bytes"), "upstream:22")
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()

	if got := conn.RemoteAddr().String(); got != "upstream:22" {
		t.Fatalf("RemoteAddr = %q, want %q", got, "upstream:22")
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
	in  chan *ConnMessage
	out chan *ConnMessage
}

func (c *fakeBidiClient) Send(m *ConnMessage) error {
	c.out <- m
	return nil
}

func (c *fakeBidiClient) Recv() (*ConnMessage, error) {
	m, ok := <-c.in
	if !ok {
		return nil, io.EOF
	}
	return m, nil
}

func TestNewServerCreateConn(t *testing.T) {
	upstream, peer := net.Pipe()
	defer upstream.Close()
	defer peer.Close()

	in := make(chan *ConnMessage, 8)
	out := make(chan *ConnMessage, 8)

	srv := NewServer(func([]byte) (net.Conn, error) { return upstream, nil })

	done := make(chan error, 1)
	go func() {
		done <- srv.CreateConn(&pipeServerStream{pipeMessageStream{in: in, out: out}})
	}()

	in <- requestMsg("req")
	in <- &ConnMessage{Message: &ConnMessage_Data{Data: []byte("ping")}}

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

func (c *errBidiClient) CreateConn(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[ConnMessage, ConnMessage], error) {
	return nil, c.err
}

func TestDialContextCreateConnError(t *testing.T) {
	wantErr := errors.New("open boom")
	if _, err := DialContext(context.Background(), &errBidiClient{err: wantErr}, nil, "addr"); !errors.Is(err, wantErr) {
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

func (s *sendErrStream) Send(*ConnMessage) error     { return s.err }
func (s *sendErrStream) Recv() (*ConnMessage, error) { return nil, io.EOF }

func (c *sendErrClient) CreateConn(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[ConnMessage, ConnMessage], error) {
	return &sendErrStream{err: c.err}, nil
}

func TestDialContextSendError(t *testing.T) {
	wantErr := errors.New("send boom")
	if _, err := DialContext(context.Background(), &sendErrClient{err: wantErr}, nil, "addr"); !errors.Is(err, wantErr) {
		t.Fatalf("DialContext error = %v, want %v", err, wantErr)
	}
}

// pipeServerStream adapts pipeMessageStream into a grpc BidiStreamingServer.
type pipeServerStream struct {
	pipeMessageStream
}

func (p *pipeServerStream) SetHeader(metadata.MD) error  { return nil }
func (p *pipeServerStream) SendHeader(metadata.MD) error { return nil }
func (p *pipeServerStream) SetTrailer(metadata.MD)       {}
func (p *pipeServerStream) Context() context.Context     { return context.Background() }
func (p *pipeServerStream) SendMsg(m any) error          { return nil }
func (p *pipeServerStream) RecvMsg(m any) error          { return nil }
