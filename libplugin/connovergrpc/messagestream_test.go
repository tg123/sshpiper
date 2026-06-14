package connovergrpc

import (
	"errors"
	"io"
	"testing"
)

// fakePacketStream is an in-memory PacketStream used to drive the
// Packet-aware net.Conn adapter in tests.
type fakePacketStream struct {
	recv    []recvMsg
	recvIdx int
	sent    []*Packet
	sendErr error
}

type recvMsg struct {
	msg *Packet
	err error
}

func (s *fakePacketStream) Send(m *Packet) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.sent = append(s.sent, m)
	return nil
}

func (s *fakePacketStream) Recv() (*Packet, error) {
	if s.recvIdx >= len(s.recv) {
		return nil, io.EOF
	}
	m := s.recv[s.recvIdx]
	s.recvIdx++
	return m.msg, m.err
}

func dataMsg(b string) *Packet {
	return &Packet{Payload: &Packet_Data{Data: []byte(b)}}
}

func TestReadAcrossMultipleFrames(t *testing.T) {
	s := &fakePacketStream{recv: []recvMsg{
		{msg: dataMsg("foo")},
		{msg: dataMsg("bar")},
	}}
	c := NewConnFromPacketStream(s, "addr", nil)

	got, err := io.ReadAll(io.LimitReader(c, 6))
	if err != nil {
		t.Fatalf("ReadAll error: %v", err)
	}
	if string(got) != "foobar" {
		t.Fatalf("ReadAll = %q, want %q", got, "foobar")
	}
}

func TestReadBuffersPartialFrame(t *testing.T) {
	s := &fakePacketStream{recv: []recvMsg{{msg: dataMsg("hello")}}}
	c := NewConnFromPacketStream(s, "addr", nil)

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
	s := &fakePacketStream{recv: []recvMsg{
		{msg: dataMsg("")},
		{msg: &Packet{}},
		{msg: dataMsg("data")},
	}}
	c := NewConnFromPacketStream(s, "addr", nil)

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
	c := NewConnFromPacketStream(&fakePacketStream{}, "addr", nil)

	buf := make([]byte, 16)
	if _, err := c.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("Read error = %v, want io.EOF", err)
	}
}

func TestReadPropagatesRecvError(t *testing.T) {
	wantErr := errors.New("recv failed")
	s := &fakePacketStream{recv: []recvMsg{{err: wantErr}}}
	c := NewConnFromPacketStream(s, "addr", nil)

	buf := make([]byte, 8)
	if _, err := c.Read(buf); !errors.Is(err, wantErr) {
		t.Fatalf("Read error = %v, want %v", err, wantErr)
	}
}

func TestWriteSendsDataFrame(t *testing.T) {
	s := &fakePacketStream{}
	c := NewConnFromPacketStream(s, "addr", nil)

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

func TestWritePropagatesSendError(t *testing.T) {
	wantErr := errors.New("send failed")
	s := &fakePacketStream{sendErr: wantErr}
	c := NewConnFromPacketStream(s, "addr", nil)

	if _, err := c.Write([]byte("payload")); !errors.Is(err, wantErr) {
		t.Fatalf("Write error = %v, want %v", err, wantErr)
	}
}

func TestRemoteAddr(t *testing.T) {
	c := NewConnFromPacketStream(&fakePacketStream{}, "upstream:22", nil)
	if got := c.RemoteAddr().String(); got != "upstream:22" {
		t.Fatalf("RemoteAddr = %q, want %q", got, "upstream:22")
	}
}

// pipePacketStream connects two endpoints so that a frame sent on one end can
// be read on the other, exercising a full round-trip over the adapter.
type pipePacketStream struct {
	in  chan *Packet
	out chan *Packet
}

func (p *pipePacketStream) Send(m *Packet) error {
	p.out <- m
	return nil
}

func (p *pipePacketStream) Recv() (*Packet, error) {
	m, ok := <-p.in
	if !ok {
		return nil, io.EOF
	}
	return m, nil
}

func TestRoundTripBetweenTwoConns(t *testing.T) {
	a2b := make(chan *Packet, 8)
	b2a := make(chan *Packet, 8)

	clientConn := NewConnFromPacketStream(&pipePacketStream{in: b2a, out: a2b}, "server", nil)
	serverConn := NewConnFromPacketStream(&pipePacketStream{in: a2b, out: b2a}, "client", nil)

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
