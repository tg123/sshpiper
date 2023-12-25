package ioconn_test

import (
	"io"
	"testing"

	"github.com/tg123/sshpiper/libplugin/ioconn"
)

func TestListenFromSingleIO(t *testing.T) {
	in, out := io.Pipe()

	l, err := ioconn.ListenFromSingleIO(in, out)
	if err != nil {
		t.Errorf("ListenFromSingleIO returned an error: %v", err)
	}

	conn, err := l.Accept()
	if err != nil {
		t.Errorf("Accept returned an error: %v", err)
	}

	defer conn.Close()
	defer l.Close()

	go func() {
		_, _ = conn.Write([]byte("hello"))
	}()

	buf := make([]byte, 5)
	_, _ = conn.Read(buf)
	if string(buf) != "hello" {
		t.Errorf("unexpected string read: %v", string(buf))
	}
}
