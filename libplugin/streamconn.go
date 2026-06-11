package libplugin

import (
	"net"
	"time"
)

// connMessageStream is implemented by both the client and server side of the
// CreateConn bidirectional stream.
type connMessageStream interface {
	Send(*ConnMessage) error
	Recv() (*ConnMessage, error)
}

type streamAddr string

func (a streamAddr) Network() string { return "sshpiper-plugin-conn" }
func (a streamAddr) String() string  { return string(a) }

// streamConn adapts a CreateConn bidirectional stream into a net.Conn by
// tunneling the connection data through ConnMessage data frames.
type streamConn struct {
	stream  connMessageStream
	onClose func() error
	addr    string
	readbuf []byte
}

// NewConnFromStream wraps a CreateConn bidirectional stream as a net.Conn.
// The data exchanged on the connection is tunneled through ConnMessage data
// frames. onClose, when not nil, is invoked once when the connection is closed.
func NewConnFromStream(stream connMessageStream, addr string, onClose func() error) net.Conn {
	return &streamConn{
		stream:  stream,
		onClose: onClose,
		addr:    addr,
	}
}

func (c *streamConn) Read(b []byte) (int, error) {
	for len(c.readbuf) == 0 {
		msg, err := c.stream.Recv()
		if err != nil {
			return 0, err
		}
		c.readbuf = msg.GetData()
	}

	n := copy(b, c.readbuf)
	c.readbuf = c.readbuf[n:]
	return n, nil
}

func (c *streamConn) Write(b []byte) (int, error) {
	if err := c.stream.Send(&ConnMessage{
		Message: &ConnMessage_Data{Data: b},
	}); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *streamConn) Close() error {
	if c.onClose != nil {
		return c.onClose()
	}
	return nil
}

func (c *streamConn) LocalAddr() net.Addr {
	return streamAddr("sshpiper-plugin-conn:local")
}

func (c *streamConn) RemoteAddr() net.Addr {
	return streamAddr(c.addr)
}

func (c *streamConn) SetDeadline(t time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return nil }
