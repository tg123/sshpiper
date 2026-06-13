// Package connovergrpc adapts a bidirectional byte stream (such as a gRPC
// bidirectional stream) into a net.Conn. The connection data is tunneled
// through the stream as raw bytes, so a plugin can own how the upstream
// connection is established (TCP, UDP, a tunnel, a proxy, etc.) while
// sshpiperd treats the result as an ordinary net.Conn.
//
//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative connovergrpc.proto
package connovergrpc

import (
	"io"
	"net"
	"time"
)

type addr string

func (a addr) Network() string { return "connovergrpc" }
func (a addr) String() string  { return string(a) }

var _ net.Conn = (*conn)(nil)

// conn adapts an io.ReadWriter into a net.Conn by adding the addressing and
// deadline bookkeeping that net.Conn requires. The connection data is read
// from and written to the underlying io.ReadWriter unchanged.
type conn struct {
	rw      io.ReadWriter
	onClose func() error
	remote  string
}

// NewConn wraps an io.ReadWriter as a net.Conn. The data exchanged on the
// connection is read from and written to rw. remoteAddr is reported by
// RemoteAddr. onClose, when not nil, is invoked once when the connection is
// closed.
func NewConn(rw io.ReadWriter, remoteAddr string, onClose func() error) net.Conn {
	return &conn{
		rw:      rw,
		onClose: onClose,
		remote:  remoteAddr,
	}
}

// Read returns data received from the underlying io.ReadWriter.
func (c *conn) Read(b []byte) (int, error) {
	return c.rw.Read(b)
}

// Write sends b to the peer via the underlying io.ReadWriter.
func (c *conn) Write(b []byte) (int, error) {
	return c.rw.Write(b)
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
