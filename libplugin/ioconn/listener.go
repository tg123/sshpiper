package ioconn

import (
	"io"
	"net"
)

type singleConnListener struct {
	conn
	used chan int
}

// Accept implements net.Listener
func (l *singleConnListener) Accept() (net.Conn, error) {
	<-l.used
	return &l.conn, nil
}

// Addr implements net.Listener
func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// Close implements net.Listener
func (l *singleConnListener) Close() error {
	return l.conn.Close()
}

// ListenFromSingleIO creates a net.Listener from a single input/output connection.
// It takes an io.ReadCloser and an io.WriteCloser as parameters and returns a net.Listener and an error.
// The returned net.Listener can be used to accept incoming connections.
func ListenFromSingleIO(in io.ReadCloser, out io.WriteCloser) (net.Listener, error) {
	l := &singleConnListener{
		conn{in, out},
		make(chan int, 1),
	}

	l.used <- 1 // ready for accept
	return l, nil
}
