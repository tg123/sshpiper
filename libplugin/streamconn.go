package libplugin

import (
	"net"

	"github.com/tg123/sshpiper/libplugin/connovergrpc"
)

// connMessageStream is implemented by both the client and server side of the
// CreateConn bidirectional stream.
type connMessageStream interface {
	Send(*ConnMessage) error
	Recv() (*ConnMessage, error)
}

// connMessageByteStream adapts the CreateConn gRPC stream, whose frames are
// ConnMessage protobuf messages, to connovergrpc.Stream's raw byte transport.
type connMessageByteStream struct {
	stream connMessageStream
}

func (s connMessageByteStream) Send(b []byte) error {
	return s.stream.Send(&ConnMessage{
		Message: &ConnMessage_Data{Data: b},
	})
}

func (s connMessageByteStream) Recv() ([]byte, error) {
	msg, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return msg.GetData(), nil
}

// NewConnFromStream wraps a CreateConn bidirectional stream as a net.Conn.
// The data exchanged on the connection is tunneled through ConnMessage data
// frames. onClose, when not nil, is invoked once when the connection is closed.
func NewConnFromStream(stream connMessageStream, addr string, onClose func() error) net.Conn {
	return connovergrpc.NewConn(connMessageByteStream{stream: stream}, addr, onClose)
}
