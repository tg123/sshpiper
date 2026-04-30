package admin

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/tg123/sshpiper/libadmin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server is the in-process admin gRPC service for a single sshpiperd
// instance. It wraps a Registry plus identifying metadata.
type Server struct {
	libadmin.UnimplementedSshPiperAdminServer

	registry  *Registry
	startedAt time.Time
	id        string
	version   string
	sshAddr   string
}

// NewServer returns a Server bound to the given Registry. id and version are
// echoed back to clients via ServerInfo; sshAddr is the listening address of
// the SSH proxy this admin server represents.
func NewServer(reg *Registry, id, version, sshAddr string) *Server {
	if id == "" {
		host, _ := os.Hostname()
		id = fmt.Sprintf("%s/%s", host, sshAddr)
	}
	return &Server{
		registry:  reg,
		startedAt: time.Now(),
		id:        id,
		version:   version,
		sshAddr:   sshAddr,
	}
}

// Register attaches the admin service to grpcServer.
func (s *Server) Register(grpcServer *grpc.Server) {
	libadmin.RegisterSshPiperAdminServer(grpcServer, s)
}

// Serve starts the gRPC server on lis. It returns when lis is closed or
// the server's Serve call fails.
func (s *Server) Serve(lis net.Listener, grpcServer *grpc.Server) error {
	s.Register(grpcServer)
	return grpcServer.Serve(lis)
}

// ServerInfo implements libadmin.SshPiperAdminServer.
func (s *Server) ServerInfo(_ context.Context, _ *libadmin.ServerInfoRequest) (*libadmin.ServerInfoResponse, error) {
	return &libadmin.ServerInfoResponse{
		Id:        s.id,
		Version:   s.version,
		SshAddr:   s.sshAddr,
		StartedAt: s.startedAt.Unix(),
	}, nil
}

// ListSessions implements libadmin.SshPiperAdminServer.
func (s *Server) ListSessions(_ context.Context, _ *libadmin.ListSessionsRequest) (*libadmin.ListSessionsResponse, error) {
	sessions := s.registry.List()
	out := make([]*libadmin.Session, 0, len(sessions))
	for _, sess := range sessions {
		_, bc, ok := s.registry.Get(sess.ID)
		streamable := ok && bc.HasHeader()
		out = append(out, &libadmin.Session{
			Id:             sess.ID,
			DownstreamUser: sess.DownstreamUser,
			DownstreamAddr: sess.DownstreamAddr,
			UpstreamUser:   sess.UpstreamUser,
			UpstreamAddr:   sess.UpstreamAddr,
			StartedAt:      sess.StartedAt.Unix(),
			Streamable:     streamable,
		})
	}
	return &libadmin.ListSessionsResponse{Sessions: out}, nil
}

// KillSession implements libadmin.SshPiperAdminServer.
func (s *Server) KillSession(_ context.Context, req *libadmin.KillSessionRequest) (*libadmin.KillSessionResponse, error) {
	if req.GetId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "id is required")
	}
	return &libadmin.KillSessionResponse{Killed: s.registry.Kill(req.GetId())}, nil
}

// StreamSession implements libadmin.SshPiperAdminServer.
func (s *Server) StreamSession(req *libadmin.StreamSessionRequest, stream libadmin.SshPiperAdmin_StreamSessionServer) error {
	if req.GetId() == "" {
		return status.Errorf(codes.InvalidArgument, "id is required")
	}
	_, bc, ok := s.registry.Get(req.GetId())
	if !ok {
		return status.Errorf(codes.NotFound, "session %q not found", req.GetId())
	}

	frames, cancel := bc.Subscribe(req.GetReplay())
	defer cancel()

	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case f, ok := <-frames:
			if !ok {
				return nil
			}
			msg, err := frameToProto(f)
			if err != nil {
				return err
			}
			if err := stream.Send(msg); err != nil {
				return err
			}
		}
	}
}

func frameToProto(f Frame) (*libadmin.SessionFrame, error) {
	switch f.Kind {
	case "header":
		return &libadmin.SessionFrame{
			Frame: &libadmin.SessionFrame_Header{
				Header: &libadmin.AsciicastHeader{
					Width:     int32(f.Width),  //nolint:gosec // dimensions fit
					Height:    int32(f.Height), //nolint:gosec // dimensions fit
					Timestamp: f.Time.Unix(),
					Env:       f.Env,
					ChannelId: f.ChannelID,
				},
			},
		}, nil
	case "o", "i":
		return &libadmin.SessionFrame{
			Frame: &libadmin.SessionFrame_Event{
				Event: &libadmin.AsciicastEvent{
					Time:      0, // relative time is computed client-side from arrival
					Kind:      f.Kind,
					Data:      f.Data,
					ChannelId: f.ChannelID,
				},
			},
		}, nil
	case "r":
		// asciicast resize payload is "WIDTHxHEIGHT" as bytes
		data := []byte(fmt.Sprintf("%dx%d", f.Width, f.Height))
		return &libadmin.SessionFrame{
			Frame: &libadmin.SessionFrame_Event{
				Event: &libadmin.AsciicastEvent{
					Time:      0,
					Kind:      f.Kind,
					Data:      data,
					ChannelId: f.ChannelID,
				},
			},
		}, nil
	}
	return nil, fmt.Errorf("unknown frame kind %q", f.Kind)
}
