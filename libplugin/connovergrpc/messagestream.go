package connovergrpc

import "net"

// MessageStream is a bidirectional stream of ConnMessage frames, implemented by
// both the client and server side of a gRPC bidirectional stream that uses
// ConnMessage as its message type.
type MessageStream interface {
	Send(*ConnMessage) error
	Recv() (*ConnMessage, error)
}

// messageByteStream adapts a MessageStream, whose frames are ConnMessage
// protobuf messages, to the raw byte transport expected by NewConn. Only the
// data frames are tunneled; the initial request frame is handled by the caller
// before the stream is wrapped as a net.Conn.
type messageByteStream struct {
	stream MessageStream
}

func (s messageByteStream) Send(b []byte) error {
	return s.stream.Send(&ConnMessage{
		Message: &ConnMessage_Data{Data: b},
	})
}

func (s messageByteStream) Recv() ([]byte, error) {
	msg, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	return msg.GetData(), nil
}

// NewConnFromMessageStream wraps a ConnMessage bidirectional stream as a
// net.Conn. The data exchanged on the connection is tunneled through
// ConnMessage data frames. remoteAddr is reported by RemoteAddr. onClose, when
// not nil, is invoked once when the connection is closed.
func NewConnFromMessageStream(stream MessageStream, remoteAddr string, onClose func() error) net.Conn {
	return NewConn(messageByteStream{stream: stream}, remoteAddr, onClose)
}
