package connovergrpc

import (
	"errors"
	"io"
	"testing"
)

// fakeMessageStream is an in-memory MessageStream used to drive the
// ConnMessage-aware net.Conn adapter in tests.
type fakeMessageStream struct {
	recv    []recvMsg
	recvIdx int
	sent    []*ConnMessage
	sendErr error
}

type recvMsg struct {
	msg *ConnMessage
	err error
}

func (s *fakeMessageStream) Send(m *ConnMessage) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.sent = append(s.sent, m)
	return nil
}

func (s *fakeMessageStream) Recv() (*ConnMessage, error) {
	if s.recvIdx >= len(s.recv) {
		return nil, io.EOF
	}
	m := s.recv[s.recvIdx]
	s.recvIdx++
	return m.msg, m.err
}

func TestNewConnFromMessageStreamRead(t *testing.T) {
	s := &fakeMessageStream{recv: []recvMsg{
		{msg: &ConnMessage{Message: &ConnMessage_Data{Data: []byte("hel")}}},
		{msg: &ConnMessage{Message: &ConnMessage_Data{Data: []byte("lo")}}},
	}}
	c := NewConnFromMessageStream(s, "addr", nil)

	got, err := io.ReadAll(io.LimitReader(c, 5))
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("ReadAll = %q, want %q", got, "hello")
	}
}

func TestNewConnFromMessageStreamReadError(t *testing.T) {
	wantErr := errors.New("recv failed")
	s := &fakeMessageStream{recv: []recvMsg{{err: wantErr}}}
	c := NewConnFromMessageStream(s, "addr", nil)

	buf := make([]byte, 8)
	if _, err := c.Read(buf); !errors.Is(err, wantErr) {
		t.Fatalf("Read error = %v, want %v", err, wantErr)
	}
}

func TestNewConnFromMessageStreamWrite(t *testing.T) {
	s := &fakeMessageStream{}
	c := NewConnFromMessageStream(s, "addr", nil)

	if _, err := c.Write([]byte("payload")); err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if len(s.sent) != 1 {
		t.Fatalf("sent %d frames, want 1", len(s.sent))
	}
	if got := string(s.sent[0].GetData()); got != "payload" {
		t.Fatalf("sent data = %q, want %q", got, "payload")
	}
}

func TestNewConnFromMessageStreamWriteError(t *testing.T) {
	wantErr := errors.New("send failed")
	s := &fakeMessageStream{sendErr: wantErr}
	c := NewConnFromMessageStream(s, "addr", nil)

	if _, err := c.Write([]byte("payload")); !errors.Is(err, wantErr) {
		t.Fatalf("Write error = %v, want %v", err, wantErr)
	}
}

func TestNewConnFromMessageStreamClose(t *testing.T) {
	called := 0
	c := NewConnFromMessageStream(&fakeMessageStream{}, "addr", func() error {
		called++
		return nil
	})

	if err := c.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}
	if called != 1 {
		t.Fatalf("onClose called %d times, want 1", called)
	}
}

func TestNewConnFromMessageStreamRemoteAddr(t *testing.T) {
	c := NewConnFromMessageStream(&fakeMessageStream{}, "upstream:22", nil)
	if got := c.RemoteAddr().String(); got != "upstream:22" {
		t.Fatalf("RemoteAddr = %q, want %q", got, "upstream:22")
	}
}
