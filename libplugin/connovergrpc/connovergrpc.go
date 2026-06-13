// Package connovergrpc adapts a bidirectional byte-frame stream (such as a
// gRPC bidirectional stream) into a net.Conn. The connection data is tunneled
// through the stream as raw byte frames, so a plugin can own how the upstream
// connection is established (TCP, UDP, a tunnel, a proxy, etc.) while
// sshpiperd treats the result as an ordinary net.Conn.
//
//go:generate protoc --go_out=. --go_opt=paths=source_relative connovergrpc.proto
package connovergrpc

import (
	"net"
	"time"
)

// Stream is the minimal bidirectional byte-frame transport that NewConn adapts
// into a net.Conn. Both the gRPC client and server side of the CreateConn
// stream are wrapped to satisfy this interface: Send delivers a frame to the
// peer and Recv blocks until the next frame (or an error such as io.EOF) is
// available.
type Stream interface {
	Send([]byte) error
	Recv() ([]byte, error)
}

type addr string

func (a addr) Network() string { return "connovergrpc" }
func (a addr) String() string  { return string(a) }

var _ net.Conn = (*conn)(nil)

// conn adapts a Stream into a net.Conn by tunneling the connection data
// through the stream's byte frames.
type conn struct {
	stream  Stream
	onClose func() error
	remote  string
	readbuf []byte
}

// NewConn wraps a bidirectional byte-frame Stream as a net.Conn. The data
// exchanged on the connection is tunneled through the stream's frames.
// remoteAddr is reported by RemoteAddr. onClose, when not nil, is invoked once
// when the connection is closed.
func NewConn(stream Stream, remoteAddr string, onClose func() error) net.Conn {
	return &conn{
		stream:  stream,
		onClose: onClose,
		remote:  remoteAddr,
	}
}

// Read returns data received from the stream. It buffers any bytes that do not
// fit into b so that frame boundaries do not have to align with read sizes.
func (c *conn) Read(b []byte) (int, error) {
	for len(c.readbuf) == 0 {
		data, err := c.stream.Recv()
		if err != nil {
			return 0, err
		}
		c.readbuf = data
	}

	n := copy(b, c.readbuf)
	c.readbuf = c.readbuf[n:]
	return n, nil
}

// Write sends b to the peer as a single stream frame.
func (c *conn) Write(b []byte) (int, error) {
	if err := c.stream.Send(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close invokes the onClose hook, if any, exactly once.
func (c *conn) Close() error {
	if c.onClose != nil {
		return c.onClose()
	}
	return nil
}

// LocalAddr returns a synthetic local address.
func (c *conn) LocalAddr() net.Addr {
	return addr("connovergrpc:local")
}

// RemoteAddr returns the remote address provided to NewConn.
func (c *conn) RemoteAddr() net.Addr {
	return addr(c.remote)
}

// SetDeadline is a no-op: deadlines are not supported by the underlying stream.
func (c *conn) SetDeadline(t time.Time) error { return nil }

// SetReadDeadline is a no-op: deadlines are not supported by the underlying stream.
func (c *conn) SetReadDeadline(t time.Time) error { return nil }

// SetWriteDeadline is a no-op: deadlines are not supported by the underlying stream.
func (c *conn) SetWriteDeadline(t time.Time) error { return nil }
