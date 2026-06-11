package libplugin

import (
	"io"
	"net"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeCreateConnStream is a minimal in-memory implementation of the CreateConn
// bidirectional stream used to exercise the server handler in tests.
type fakeCreateConnStream struct {
	SshPiperPlugin_CreateConnServer

	in  chan *ConnMessage
	out chan *ConnMessage
}

func (f *fakeCreateConnStream) Recv() (*ConnMessage, error) {
	msg, ok := <-f.in
	if !ok {
		return nil, io.EOF
	}
	return msg, nil
}

func (f *fakeCreateConnStream) Send(msg *ConnMessage) error {
	f.out <- msg
	return nil
}

func TestServerCreateConnUnimplemented(t *testing.T) {
	s := &server{}

	stream := &fakeCreateConnStream{
		in:  make(chan *ConnMessage),
		out: make(chan *ConnMessage),
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
		in:  make(chan *ConnMessage, 2),
		out: make(chan *ConnMessage, 1),
	}

	done := make(chan error, 1)
	go func() {
		done <- s.CreateConn(stream)
	}()

	// send the initial request describing the connection to create
	stream.in <- &ConnMessage{
		Message: &ConnMessage_Request{
			Request: &CreateConnRequest{
				Meta: &ConnMeta{UserName: "alice"},
				Uri:  "tcp://upstream:22",
			},
		},
	}

	// data written by the downstream side should reach the upstream conn
	stream.in <- &ConnMessage{
		Message: &ConnMessage_Data{Data: []byte("ping")},
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
