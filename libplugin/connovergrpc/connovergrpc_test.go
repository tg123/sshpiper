package connovergrpc

import (
	"errors"
	"io"
	"testing"
	"time"
)

// fakeRW is an in-memory io.ReadWriter used to drive the net.Conn adapter in
// tests. Read returns readData (and io.EOF once exhausted) unless readErr is
// set; Write records the bytes unless writeErr is set.
type fakeRW struct {
	readData []byte
	readErr  error
	written  []byte
	writeErr error
}

func (f *fakeRW) Read(b []byte) (int, error) {
	if f.readErr != nil {
		return 0, f.readErr
	}
	if len(f.readData) == 0 {
		return 0, io.EOF
	}
	n := copy(b, f.readData)
	f.readData = f.readData[n:]
	return n, nil
}

func (f *fakeRW) Write(b []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	f.written = append(f.written, b...)
	return len(b), nil
}

func TestReadDelegatesToReadWriter(t *testing.T) {
	rw := &fakeRW{readData: []byte("hello")}
	c := NewConn(rw, "addr", nil)

	got, err := io.ReadAll(io.LimitReader(c, 5))
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("ReadAll = %q, want %q", got, "hello")
	}
}

func TestReadPropagatesError(t *testing.T) {
	wantErr := errors.New("boom")
	c := NewConn(&fakeRW{readErr: wantErr}, "addr", nil)

	buf := make([]byte, 16)
	if _, err := c.Read(buf); !errors.Is(err, wantErr) {
		t.Fatalf("Read error = %v, want %v", err, wantErr)
	}
}

func TestWriteDelegatesToReadWriter(t *testing.T) {
	rw := &fakeRW{}
	c := NewConn(rw, "addr", nil)

	n, err := c.Write([]byte("payload"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != len("payload") {
		t.Fatalf("Write n = %d, want %d", n, len("payload"))
	}
	if string(rw.written) != "payload" {
		t.Fatalf("written = %q, want %q", rw.written, "payload")
	}
}

func TestWritePropagatesError(t *testing.T) {
	wantErr := errors.New("send failed")
	c := NewConn(&fakeRW{writeErr: wantErr}, "addr", nil)

	n, err := c.Write([]byte("payload"))
	if !errors.Is(err, wantErr) {
		t.Fatalf("Write error = %v, want %v", err, wantErr)
	}
	if n != 0 {
		t.Fatalf("Write n = %d, want 0 on error", n)
	}
}

func TestCloseInvokesHook(t *testing.T) {
	called := 0
	wantErr := errors.New("close error")
	c := NewConn(&fakeRW{}, "addr", func() error {
		called++
		return wantErr
	})

	if err := c.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("Close error = %v, want %v", err, wantErr)
	}
	if called != 1 {
		t.Fatalf("onClose called %d times, want 1", called)
	}
}

func TestCloseWithoutHook(t *testing.T) {
	c := NewConn(&fakeRW{}, "addr", nil)
	if err := c.Close(); err != nil {
		t.Fatalf("Close error = %v, want nil", err)
	}
}

func TestAddrs(t *testing.T) {
	c := NewConn(&fakeRW{}, "upstream:2222", nil)

	if got := c.RemoteAddr().String(); got != "upstream:2222" {
		t.Fatalf("RemoteAddr = %q, want %q", got, "upstream:2222")
	}
	if got := c.RemoteAddr().Network(); got != "connovergrpc" {
		t.Fatalf("RemoteAddr network = %q, want %q", got, "connovergrpc")
	}
	if got := c.LocalAddr().String(); got != "connovergrpc:local" {
		t.Fatalf("LocalAddr = %q, want %q", got, "connovergrpc:local")
	}
}

func TestDeadlinesAreNoOps(t *testing.T) {
	c := NewConn(&fakeRW{}, "addr", nil)
	now := time.Now()
	if err := c.SetDeadline(now); err != nil {
		t.Fatalf("SetDeadline error = %v", err)
	}
	if err := c.SetReadDeadline(now); err != nil {
		t.Fatalf("SetReadDeadline error = %v", err)
	}
	if err := c.SetWriteDeadline(now); err != nil {
		t.Fatalf("SetWriteDeadline error = %v", err)
	}
}
