package connovergrpc

import (
	"context"
	"io"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CreateConnFunc dials the upstream identified by uri. The uri format is
// defined by the application; connovergrpc does not interpret it.
type CreateConnFunc func(uri string) (net.Conn, error)

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

func (s *connOverGrpcServer) CreateConn(stream grpc.BidiStreamingServer[Packet, Packet]) error {
	return ServeCreateConn(stream, s.create)
}

// ServeCreateConn implements the server side of a CreateConn stream: it reads
// the first (DialRequest) packet, calls create with the request URI, then
// tunnels bytes between the returned conn and the stream until either side
// closes.
func ServeCreateConn(stream PacketStream, create CreateConnFunc) error {
	if create == nil {
		return status.Error(codes.Unimplemented, "create conn callback not configured")
	}

	pkt, err := stream.Recv()
	if err != nil {
		if err == io.EOF {
			return status.Error(codes.InvalidArgument, "stream closed before DialRequest")
		}
		return err
	}

	dial, ok := pkt.Payload.(*Packet_DialRequest)
	if !ok || dial.DialRequest == nil {
		return status.Error(codes.InvalidArgument, "first packet must be a DialRequest")
	}

	uri := dial.DialRequest.Uri
	upstream, err := create(uri)
	if err != nil {
		return err
	}
	if upstream == nil {
		return status.Error(codes.Internal, "create conn callback returned nil conn")
	}
	defer upstream.Close()

	piped := NewConnFromPacketStream(stream, uri, nil)

	// Tunnel bytes in both directions until one side errors or EOFs.
	//
	// Each goroutine closes upstream on exit so the *upstream-side* of
	// the other goroutine (its upstream.Read or upstream.Write) is
	// unblocked immediately, not only when the deferred upstream.Close
	// at the end of this function runs.
	//
	// We do not wait for both goroutines before returning: the
	// stream-reading direction (io.Copy(upstream, piped)) can be parked
	// inside stream.Recv after upstream is closed, and a server-side
	// gRPC stream has no in-handler cancel hook — stream.Context() is
	// only cancelled after this handler returns. Waiting here would
	// deadlock in the "upstream EOF first" case. The orphan goroutine
	// is bounded: gRPC tears down the stream when this handler returns,
	// which makes stream.Recv return promptly.
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(upstream, piped)
		upstream.Close()
		errc <- err
	}()
	go func() {
		_, err := io.Copy(piped, upstream)
		upstream.Close()
		errc <- err
	}()

	return <-errc
}

// DialContext opens a CreateConn stream on client, sends uri as the first
// (DialRequest) packet, and returns a net.Conn that tunnels the connection
// bytes. uri is also reported by the returned conn's RemoteAddr. The
// stream is bound to a child of ctx that is cancelled when the returned conn
// is closed.
func DialContext(ctx context.Context, client ConnOverGrpcClient, uri string) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)

	stream, err := client.CreateConn(ctx)
	if err != nil {
		cancel()
		return nil, err
	}

	if err := stream.Send(&Packet{
		Payload: &Packet_DialRequest{DialRequest: &DialRequest{Uri: uri}},
	}); err != nil {
		cancel()
		return nil, err
	}

	return NewConnFromPacketStream(stream, uri, func() error {
		// Half-close the send side so the server observes EOF and can
		// finish draining; then cancel the context to tear down the
		// stream entirely.
		closeErr := stream.CloseSend()
		cancel()
		return closeErr
	}), nil
}
