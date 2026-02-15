package libplugin

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestServerCreateConnUnimplemented(t *testing.T) {
	s := &server{}

	_, err := s.CreateConn(context.Background(), &CreateConnRequest{})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("expected unimplemented error, got %v", err)
	}
}

func TestServerCreateConnCallback(t *testing.T) {
	s := &server{
		config: SshPiperPluginConfig{
			CreateConnCallback: func(conn ConnMetadata, uri string) (string, error) {
				if conn.User() != "alice" {
					t.Fatalf("unexpected user %q", conn.User())
				}
				if uri != "tcp://upstream:22" {
					t.Fatalf("unexpected uri %q", uri)
				}
				return "tcp://127.0.0.1:2222", nil
			},
		},
	}

	resp, err := s.CreateConn(context.Background(), &CreateConnRequest{
		Meta: &ConnMeta{UserName: "alice"},
		Uri:  "tcp://upstream:22",
	})
	if err != nil {
		t.Fatalf("CreateConn returned error: %v", err)
	}

	if resp.GetUri() != "tcp://127.0.0.1:2222" {
		t.Fatalf("unexpected response uri %q", resp.GetUri())
	}
}
