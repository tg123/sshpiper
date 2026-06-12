package connovergrpc

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// fakeStream is an in-memory implementation of Stream used to drive the
// net.Conn adapter in tests.
type fakeStream struct {
	// recv frames returned by successive Recv calls, in order.
	recv []recvFrame
	// recvIdx is the index of the next frame to return from recv.
	recvIdx int
	// sent records every frame passed to Send.
	sent [][]byte
	// sendErr, when set, is returned by Send instead of recording the frame.
	sendErr error
}

type recvFrame struct {
	data []byte
	err  error
}

func (s *fakeStream) Send(b []byte) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	// copy to detect accidental aliasing of caller buffers
	cp := make([]byte, len(b))
	copy(cp, b)
	s.sent = append(s.sent, cp)
	return nil
}

func (s *fakeStream) Recv() ([]byte, error) {
	if s.recvIdx >= len(s.recv) {
		return nil, io.EOF
	}
	f := s.recv[s.recvIdx]
	s.recvIdx++
	return f.data, f.err
}

func TestNewConnImplementsNetConn(t *testing.T) {
	var _ net.Conn = NewConn(&fakeStream{}, "addr", nil)
}

func TestReadSingleFrame(t *testing.T) {
	s := &fakeStream{recv: []recvFrame{{data: []byte("hello")}}}
	c := NewConn(s, "addr", nil)

	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if got := string(buf[:n]); got != "hello" {
		t.Fatalf("Read = %q, want %q", got, "hello")
	}
}

func TestReadAcrossMultipleFrames(t *testing.T) {
	s := &fakeStream{recv: []recvFrame{
		{data: []byte("foo")},
		{data: []byte("bar")},
	}}
	c := NewConn(s, "addr", nil)

	got, err := io.ReadAll(io.LimitReader(c, 6))
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(got) != "foobar" {
		t.Fatalf("ReadAll = %q, want %q", got, "foobar")
	}
}

func TestReadBuffersPartialFrame(t *testing.T) {
	s := &fakeStream{recv: []recvFrame{{data: []byte("hello")}}}
	c := NewConn(s, "addr", nil)

	// Read fewer bytes than the frame contains; the remainder must be buffered.
	buf := make([]byte, 2)
	n, err := c.Read(buf)
	if err != nil || n != 2 || string(buf[:n]) != "he" {
		t.Fatalf("first Read = %q, %d, %v", buf[:n], n, err)
	}

	buf = make([]byte, 16)
	n, err = c.Read(buf)
	if err != nil || string(buf[:n]) != "llo" {
		t.Fatalf("second Read = %q, %d, %v", buf[:n], n, err)
	}
}

func TestReadSkipsEmptyFrames(t *testing.T) {
	s := &fakeStream{recv: []recvFrame{
		{data: []byte{}},
		{data: nil},
		{data: []byte("data")},
	}}
	c := NewConn(s, "addr", nil)

	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if string(buf[:n]) != "data" {
		t.Fatalf("Read = %q, want %q", buf[:n], "data")
	}
}

func TestReadEOF(t *testing.T) {
	s := &fakeStream{}
	c := NewConn(s, "addr", nil)

	buf := make([]byte, 16)
	_, err := c.Read(buf)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Read error = %v, want io.EOF", err)
	}
}

func TestReadPropagatesError(t *testing.T) {
	wantErr := errors.New("boom")
	s := &fakeStream{recv: []recvFrame{{err: wantErr}}}
	c := NewConn(s, "addr", nil)

	buf := make([]byte, 16)
	_, err := c.Read(buf)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Read error = %v, want %v", err, wantErr)
	}
}

func TestWrite(t *testing.T) {
	s := &fakeStream{}
	c := NewConn(s, "addr", nil)

	n, err := c.Write([]byte("payload"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != len("payload") {
		t.Fatalf("Write n = %d, want %d", n, len("payload"))
	}
	if len(s.sent) != 1 || string(s.sent[0]) != "payload" {
		t.Fatalf("sent = %q, want one frame %q", s.sent, "payload")
	}
}

func TestWritePropagatesError(t *testing.T) {
	wantErr := errors.New("send failed")
	s := &fakeStream{sendErr: wantErr}
	c := NewConn(s, "addr", nil)

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
	c := NewConn(&fakeStream{}, "addr", func() error {
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
	c := NewConn(&fakeStream{}, "addr", nil)
	if err := c.Close(); err != nil {
		t.Fatalf("Close error = %v, want nil", err)
	}
}

func TestAddrs(t *testing.T) {
	c := NewConn(&fakeStream{}, "upstream:2222", nil)

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
	c := NewConn(&fakeStream{}, "addr", nil)
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

// pipeStream connects two fakeStream-like endpoints so that a frame sent on one
// end can be read on the other, exercising a full round-trip over the adapter.
type pipeStream struct {
	in  chan []byte
	out chan []byte
}

func (p *pipeStream) Send(b []byte) error {
	cp := make([]byte, len(b))
	copy(cp, b)
	p.out <- cp
	return nil
}

func (p *pipeStream) Recv() ([]byte, error) {
	b, ok := <-p.in
	if !ok {
		return nil, io.EOF
	}
	return b, nil
}

func TestRoundTripBetweenTwoConns(t *testing.T) {
	a2b := make(chan []byte, 8)
	b2a := make(chan []byte, 8)

	clientConn := NewConn(&pipeStream{in: b2a, out: a2b}, "server", nil)
	serverConn := NewConn(&pipeStream{in: a2b, out: b2a}, "client", nil)

	// echo server
	go func() {
		buf := make([]byte, 32)
		n, err := serverConn.Read(buf)
		if err != nil {
			return
		}
		_, _ = serverConn.Write(buf[:n])
	}()

	if _, err := clientConn.Write([]byte("ping")); err != nil {
		t.Fatalf("client Write error: %v", err)
	}

	buf := make([]byte, 32)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("client Read error: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("round-trip = %q, want %q", buf[:n], "ping")
	}
}
