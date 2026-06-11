package main

import (
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/ssh"
)

// helper: construct a channel-data packet wire bytes (msg type 94)
// addressed to channel id
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

func TestEnvInjector_InjectsOncePerChannelOnFirstDownstreamPacket(t *testing.T) {
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

	// Downstream sends first channel-data packet for channel 7.
	if m, _, err := inj.down(channelDataPkt(7, []byte("ping"))); err != nil || m != ssh.PipePacketHookTransform {
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

	// A second downstream packet for the same channel must NOT re-inject.
	if _, _, err := inj.down(channelDataPkt(7, []byte("pong"))); err != nil {
		t.Fatal(err)
	}
	if got := len(injected); got != 2 {
		t.Errorf("second downstream packet should not re-inject; got %d total", got)
	}
}

func TestEnvInjector_SkipsNonChannelScopedMessages(t *testing.T) {
	called := false
	writer := func(p []byte) error { called = true; return nil }
	inj := &envInjector{
		writeUpstream: writer,
		env:           map[string]string{"FOO": "bar"},
		injected:      map[uint32]bool{},
	}

	// msg 90 (channel-open) has a length prefix at pkt[1:5], not a
	// channel id, and clients can't send channel-scoped traffic before
	// open-confirm anyway — must not trigger injection.
	if _, _, err := inj.down(channelOpenPkt()); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("env injected for channel-open packet")
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

	inj.down(channelDataPkt(7, nil)) // +1
	inj.down(channelDataPkt(7, nil)) // no change
	inj.down(channelDataPkt(8, nil)) // +1

	if writeCount != 2 {
		t.Errorf("expected 2 injections (one per channel), got %d", writeCount)
	}
}
