package connovergrpc

import (
	"net"
	"sync"
)

// PacketStream is a bidirectional stream of Packet frames, implemented by both
// the client and server side of the CreateConn gRPC bidirectional stream.
type PacketStream interface {
	Send(*Packet) error
	Recv() (*Packet, error)
}

// packetReadWriter adapts a PacketStream into an io.ReadWriter. Only data
// packets are tunneled; the initial DialRequest packet is consumed by the
// caller before the stream is wrapped as a net.Conn. Read buffers any bytes
// that do not fit into the caller's buffer so that packet boundaries need
// not align with read sizes.
//
// readMu / writeMu serialize concurrent Read or Write calls into the
// underlying PacketStream — grpc streams do not support concurrent Send or
// concurrent Recv calls — while still allowing one Read and one Write to be
// in flight concurrently, as net.Conn requires.
type packetReadWriter struct {
	stream PacketStream

	readMu  sync.Mutex
	readbuf []byte

	writeMu sync.Mutex
}

// Write sends b to the peer as a single data Packet. The caller's slice is
// copied so it may be reused or mutated as soon as Write returns, per the
// net.Conn contract.
func (s *packetReadWriter) Write(b []byte) (int, error) {
	data := append([]byte(nil), b...)
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.stream.Send(&Packet{
		Payload: &Packet_Data{Data: data},
	}); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Read returns bytes received from data Packets on the stream.
func (s *packetReadWriter) Read(b []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	for len(s.readbuf) == 0 {
		pkt, err := s.stream.Recv()
		if err != nil {
			return 0, err
		}
		s.readbuf = pkt.GetData()
	}

	n := copy(b, s.readbuf)
	s.readbuf = s.readbuf[n:]
	return n, nil
}

// NewConnFromPacketStream wraps a Packet bidirectional stream as a net.Conn.
// remoteAddr is reported by RemoteAddr. onClose, when not nil, is invoked
// once when the connection is closed.
func NewConnFromPacketStream(stream PacketStream, remoteAddr string, onClose func() error) net.Conn {
	return NewConn(&packetReadWriter{stream: stream}, remoteAddr, onClose)
}
