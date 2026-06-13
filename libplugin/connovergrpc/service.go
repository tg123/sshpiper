package connovergrpc

import (
	"context"
	"io"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CreateConnFunc creates a net.Conn from the opaque request bytes carried in
// the first frame of a CreateConn stream. The request format is defined by the
// application; connovergrpc does not interpret it.
type CreateConnFunc func(request []byte) (net.Conn, error)

// connOverGrpcServer is a ready-to-register ConnOverGrpcServer that delegates
// connection creation to a CreateConnFunc.
type connOverGrpcServer struct {
	UnimplementedConnOverGrpcServer
	create CreateConnFunc
}

// NewServer returns a ConnOverGrpcServer that calls create for every incoming
// stream to obtain the net.Conn to tunnel. Register it on a gRPC server with
// RegisterConnOverGrpcServer.
func NewServer(create CreateConnFunc) ConnOverGrpcServer {
	return &connOverGrpcServer{create: create}
}

func (s *connOverGrpcServer) CreateConn(stream grpc.BidiStreamingServer[ConnMessage, ConnMessage]) error {
	return ServeCreateConn(stream, s.create)
}

// ServeCreateConn implements the server side of a CreateConn stream: it reads
// the first (request) frame, calls create to obtain the net.Conn, then tunnels
// bytes between that conn and the stream until either side closes.
func ServeCreateConn(stream MessageStream, create CreateConnFunc) error {
	msg, err := stream.Recv()
	if err != nil {
		return err
	}

	request := msg.GetRequest()
	if request == nil {
		return status.Error(codes.InvalidArgument, "first message must be a request")
	}

	upstream, err := create(request)
	if err != nil {
		return err
	}
	defer upstream.Close()

	piped := NewConnFromMessageStream(stream, "", nil)

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(upstream, piped)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(piped, upstream)
		errc <- err
	}()

	return <-errc
}

// DialContext opens a CreateConn stream on client, sends request as the first
// frame, and returns a net.Conn that tunnels the connection bytes. remoteAddr
// is reported by the returned conn's RemoteAddr. The stream is bound to a
// child of ctx that is cancelled when the returned conn is closed.
func DialContext(ctx context.Context, client ConnOverGrpcClient, request []byte, remoteAddr string) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)

	stream, err := client.CreateConn(ctx)
	if err != nil {
		cancel()
		return nil, err
	}

	if err := stream.Send(&ConnMessage{
		Message: &ConnMessage_Request{Request: request},
	}); err != nil {
		cancel()
		return nil, err
	}

	return NewConnFromMessageStream(stream, remoteAddr, func() error {
		cancel()
		return nil
	}), nil
}
