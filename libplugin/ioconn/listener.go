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

func ListenFromSingleIO(in io.ReadCloser, out io.WriteCloser) (net.Listener, error) {
	l := &singleConnListener{
		conn{in, out},
		make(chan int, 1),
	}

	l.used <- 1 // ready for accept
	return l, nil
}
