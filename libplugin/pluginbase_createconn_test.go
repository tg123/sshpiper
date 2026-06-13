package libplugin

import (
	"net"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestServerCreateConnDecodesRequestAndInvokesCallback(t *testing.T) {
	upstream, peer := net.Pipe()
	defer upstream.Close()
	defer peer.Close()

	s := &server{
		config: SshPiperPluginConfig{
			CreateConnCallback: func(conn ConnMetadata, uri string) (net.Conn, error) {
				if conn.User() != "alice" {
					t.Errorf("unexpected user %q", conn.User())
				}
				if uri != "tcp://upstream:22" {
					t.Errorf("unexpected uri %q", uri)
				}
				return upstream, nil
			},
		},
	}

	reqbytes, err := proto.Marshal(&CreateConnRequest{
		Meta: &ConnMeta{UserName: "alice"},
		Uri:  "tcp://upstream:22",
	})
	if err != nil {
		t.Fatalf("marshal request failed: %v", err)
	}

	got, err := s.createConn(reqbytes)
	if err != nil {
		t.Fatalf("createConn failed: %v", err)
	}
	if got != upstream {
		t.Fatalf("createConn returned unexpected conn")
	}
}

func TestServerCreateConnInvalidRequest(t *testing.T) {
	s := &server{
		config: SshPiperPluginConfig{
			CreateConnCallback: func(conn ConnMetadata, uri string) (net.Conn, error) {
				t.Fatal("callback should not be invoked on invalid request")
				return nil, nil
			},
		},
	}

	_, err := s.createConn([]byte("not a valid protobuf message"))
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected invalid argument error, got %v", err)
	}
}
