package main

import (
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/ssh"
)

// helper: construct a channel-request packet wire bytes (msg type 98,
// SSH_MSG_CHANNEL_REQUEST) addressed to channel id. Carries an empty
// "pty-req"-style request payload — we only need the first 5 bytes.
func channelRequestPkt(channelID uint32) []byte {
	const req = "shell"
	p := make([]byte, 1+4+4+len(req)+1)
	p[0] = msgChannelRequest
	binary.BigEndian.PutUint32(p[1:5], channelID)
	binary.BigEndian.PutUint32(p[5:9], uint32(len(req)))
	copy(p[9:], req)
	// want_reply = false (last byte already 0)
	return p
}

// helper: construct a channel-data packet wire bytes (msg type 94)
// addressed to channel id. After the msg 98 restriction this is used
// to verify the down hook does NOT trigger on non-request traffic.
func channelDataPkt(channelID uint32, data []byte) []byte {
	p := make([]byte, 9+len(data))
	p[0] = 94
	binary.BigEndian.PutUint32(p[1:5], channelID)
	binary.BigEndian.PutUint32(p[5:9], uint32(len(data)))
	copy(p[9:], data)
	return p
}

// helper: construct a channel-open packet wire bytes (msg type 90).
// pkt[1:5] is the channel-type length, not a channel id — used to
// verify the down hook ignores non-channel-scoped messages.
func channelOpenPkt() []byte {
	const ctype = "session"
	p := make([]byte, 1+4+len(ctype)+4+4+4)
	p[0] = 90
	binary.BigEndian.PutUint32(p[1:5], uint32(len(ctype)))
	copy(p[5:], ctype)
	return p
}

func TestEnvInjector_InjectsOncePerChannelOnFirstRequest(t *testing.T) {
	var injected [][]byte
	writer := func(p []byte) error {
		injected = append(injected, append([]byte(nil), p...))
		return nil
	}

	inj := &envInjector{
		writeUpstream: writer,
		env:           map[string]string{"FOO": "bar", "BAZ": "qux"},
		injected:      map[uint32]bool{},
	}

	// Channel-data alone (msg 94) must NOT trigger injection — those
	// can come from non-session channels like direct-tcpip too.
	if _, _, err := inj.down(channelDataPkt(7, []byte("ping"))); err != nil {
		t.Fatal(err)
	}
	if len(injected) != 0 {
		t.Fatalf("channel-data alone must not inject; got %d packets", len(injected))
	}

	// First channel-request for channel 7 triggers injection.
	if m, _, err := inj.down(channelRequestPkt(7)); err != nil || m != ssh.PipePacketHookTransform {
		t.Fatalf("down: method=%v err=%v", m, err)
	}

	if len(injected) != 2 {
		t.Fatalf("expected 2 injected env packets, got %d", len(injected))
	}
	for _, p := range injected {
		if p[0] != msgChannelRequest {
			t.Errorf("injected packet first byte = %d, want %d", p[0], msgChannelRequest)
		}
		if cid := binary.BigEndian.Uint32(p[1:5]); cid != 7 {
			t.Errorf("injected packet channel id = %d, want 7", cid)
		}
	}

	// A second channel-request on the same channel must NOT re-inject.
	if _, _, err := inj.down(channelRequestPkt(7)); err != nil {
		t.Fatal(err)
	}
	if got := len(injected); got != 2 {
		t.Errorf("second request should not re-inject; got %d total", got)
	}
}

func TestEnvInjector_SkipsNonRequestMessages(t *testing.T) {
	called := false
	writer := func(p []byte) error { called = true; return nil }
	inj := &envInjector{
		writeUpstream: writer,
		env:           map[string]string{"FOO": "bar"},
		injected:      map[uint32]bool{},
	}

	for _, pkt := range [][]byte{
		channelOpenPkt(),
		channelDataPkt(7, []byte("x")),
	} {
		if _, _, err := inj.down(pkt); err != nil {
			t.Fatal(err)
		}
	}
	if called {
		t.Fatal("env injected for a non-channel-request packet")
	}
}

func TestEnvInjector_PerChannelIsolation(t *testing.T) {
	writeCount := 0
	writer := func(p []byte) error { writeCount++; return nil }
	inj := &envInjector{
		writeUpstream: writer,
		env:           map[string]string{"FOO": "bar"},
		injected:      map[uint32]bool{},
	}

	inj.down(channelRequestPkt(7)) // +1
	inj.down(channelRequestPkt(7)) // no change
	inj.down(channelRequestPkt(8)) // +1

	if writeCount != 2 {
		t.Errorf("expected 2 injections (one per channel), got %d", writeCount)
	}
}
