package ioconn_test

import (
	"io"
	"testing"

	"github.com/tg123/sshpiper/libplugin/ioconn"
)

type mockReadCloser struct{}

func (m *mockReadCloser) Read(p []byte) (n int, err error) {
	return 0, io.EOF
}

func (m *mockReadCloser) Close() error {
	return nil
}

type mockWriteCloser struct{}

func (m *mockWriteCloser) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (m *mockWriteCloser) Close() error {
	return nil
}

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

	go conn.Write([]byte("hello"))
	buf := make([]byte, 5)
	conn.Read(buf)
	if string(buf) != "hello" {
		t.Errorf("unexpected string read: %v", string(buf))
	}
}
