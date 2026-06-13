package connovergrpc

import "net"

// MessageStream is a bidirectional stream of ConnMessage frames, implemented by
// both the client and server side of a gRPC bidirectional stream that uses
// ConnMessage as its message type.
type MessageStream interface {
	Send(*ConnMessage) error
	Recv() (*ConnMessage, error)
}

// messageReadWriter adapts a MessageStream, whose frames are ConnMessage
// protobuf messages, into an io.ReadWriter. Only the data frames are tunneled;
// the initial request frame is handled by the caller before the stream is
// wrapped as a net.Conn. Read buffers any bytes that do not fit into the
// caller's buffer so that frame boundaries need not align with read sizes.
type messageReadWriter struct {
	stream  MessageStream
	readbuf []byte
}

// Write sends b to the peer as a single ConnMessage data frame.
func (s *messageReadWriter) Write(b []byte) (int, error) {
	if err := s.stream.Send(&ConnMessage{
		Message: &ConnMessage_Data{Data: b},
	}); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Read returns data received from the stream's ConnMessage data frames.
func (s *messageReadWriter) Read(b []byte) (int, error) {
	for len(s.readbuf) == 0 {
		msg, err := s.stream.Recv()
		if err != nil {
			return 0, err
		}
		s.readbuf = msg.GetData()
	}

	n := copy(b, s.readbuf)
	s.readbuf = s.readbuf[n:]
	return n, nil
}

// NewConnFromMessageStream wraps a ConnMessage bidirectional stream as a
// net.Conn. The data exchanged on the connection is tunneled through
// ConnMessage data frames. remoteAddr is reported by RemoteAddr. onClose, when
// not nil, is invoked once when the connection is closed.
func NewConnFromMessageStream(stream MessageStream, remoteAddr string, onClose func() error) net.Conn {
	return NewConn(&messageReadWriter{stream: stream}, remoteAddr, onClose)
}
