package ioconn

import (
	"fmt"
	"io"
	"net"
	"time"
)

type addr string

func (a addr) Network() string {
	return "ioconn"
}

func (a addr) String() string {
	return string(a)
}

type conn struct {
	in  io.ReadCloser
	out io.WriteCloser
}

func Dial(in io.ReadCloser, out io.WriteCloser) (net.Conn, error) {
	return dial(in, out), nil
}

func dial(in io.ReadCloser, out io.WriteCloser) *conn {
	return &conn{in, out}
}

// Read reads data from the connection.
// Read can be made to time out and return an error after a fixed
// time limit; see SetDeadline and SetReadDeadline.
func (c *conn) Read(b []byte) (n int, err error) {
	return c.in.Read(b)
}

// Write writes data to the connection.
// Write can be made to time out and return an error after a fixed
// time limit; see SetDeadline and SetWriteDeadline.
func (c *conn) Write(b []byte) (n int, err error) {
	return c.out.Write(b)
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (c *conn) Close() error {
	inerr := c.in.Close()
	outerr := c.out.Close()

	if inerr == nil {
		return outerr
	}

	if outerr == nil {
		return outerr
	}

	return fmt.Errorf("io close error in: %v, out: %v", inerr, outerr)
}

// LocalAddr returns the local network address, if known.
func (c *conn) LocalAddr() net.Addr {
	return addr("ioconn:local")
}

// RemoteAddr returns the remote network address, if known.
func (c *conn) RemoteAddr() net.Addr {
	return addr("ioconn:remote")
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail instead of blocking. The deadline applies to all future
// and pending I/O, not just the immediately following call to
// Read or Write. After a deadline has been exceeded, the
// connection can be refreshed by setting a deadline in the future.
//
// If the deadline is exceeded a call to Read or Write or to other
// I/O methods will return an error that wraps os.ErrDeadlineExceeded.
// This can be tested using errors.Is(err, os.ErrDeadlineExceeded).
// The error's Timeout method will return true, but note that there
// are other possible errors for which the Timeout method will
// return true even if the deadline has not been exceeded.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful Read or Write calls.
//
// A zero value for t means I/O operations will not time out.
func (c *conn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (c *conn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (c *conn) SetWriteDeadline(t time.Time) error {
	return nil
}
