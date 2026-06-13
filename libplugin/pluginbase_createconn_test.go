package libplugin

import (
	"io"
	"net"
	"testing"

	"github.com/tg123/sshpiper/libplugin/connovergrpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// fakeCreateConnStream is a minimal in-memory implementation of the CreateConn
// bidirectional stream used to exercise the server handler in tests.
type fakeCreateConnStream struct {
	SshPiperPlugin_CreateConnServer

	in  chan *connovergrpc.ConnMessage
	out chan *connovergrpc.ConnMessage
}

func (f *fakeCreateConnStream) Recv() (*connovergrpc.ConnMessage, error) {
	msg, ok := <-f.in
	if !ok {
		return nil, io.EOF
	}
	return msg, nil
}

func (f *fakeCreateConnStream) Send(msg *connovergrpc.ConnMessage) error {
	f.out <- msg
	return nil
}

func TestServerCreateConnUnimplemented(t *testing.T) {
	s := &server{}

	stream := &fakeCreateConnStream{
		in:  make(chan *connovergrpc.ConnMessage),
		out: make(chan *connovergrpc.ConnMessage),
	}

	err := s.CreateConn(stream)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("expected unimplemented error, got %v", err)
	}
}

func TestServerCreateConnCallback(t *testing.T) {
	upstream, plugin := net.Pipe()
	defer upstream.Close()

	s := &server{
		config: SshPiperPluginConfig{
			CreateConnCallback: func(conn ConnMetadata, uri string) (net.Conn, error) {
				if conn.User() != "alice" {
					t.Errorf("unexpected user %q", conn.User())
				}
				if uri != "tcp://upstream:22" {
					t.Errorf("unexpected uri %q", uri)
				}
				return plugin, nil
			},
		},
	}

	stream := &fakeCreateConnStream{
		in:  make(chan *connovergrpc.ConnMessage, 2),
		out: make(chan *connovergrpc.ConnMessage, 1),
	}

	done := make(chan error, 1)
	go func() {
		done <- s.CreateConn(stream)
	}()

	// send the initial request describing the connection to create
	reqbytes, err := proto.Marshal(&CreateConnRequest{
		Meta: &ConnMeta{UserName: "alice"},
		Uri:  "tcp://upstream:22",
	})
	if err != nil {
		t.Fatalf("marshal request failed: %v", err)
	}
	stream.in <- &connovergrpc.ConnMessage{
		Message: &connovergrpc.ConnMessage_Request{Request: reqbytes},
	}

	// data written by the downstream side should reach the upstream conn
	stream.in <- &connovergrpc.ConnMessage{
		Message: &connovergrpc.ConnMessage_Data{Data: []byte("ping")},
	}

	buf := make([]byte, 4)
	if _, err := io.ReadFull(upstream, buf); err != nil {
		t.Fatalf("read from upstream failed: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("unexpected upstream data %q", buf)
	}

	// data written by the upstream conn should be tunneled back to the stream
	if _, err := upstream.Write([]byte("pong")); err != nil {
		t.Fatalf("write to upstream failed: %v", err)
	}

	out := <-stream.out
	if string(out.GetData()) != "pong" {
		t.Fatalf("unexpected tunneled data %q", out.GetData())
	}

	// closing the stream input ends the proxy loop
	close(stream.in)
	<-done
}
