package main

import (
	"encoding/binary"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// helper: construct a channel-open-confirmation packet wire bytes for
// recipient/sender ids
func openConfirmPkt(recipient, sender uint32) []byte {
	p := make([]byte, 17)
	p[0] = msgChannelOpenConfirm
	binary.BigEndian.PutUint32(p[1:5], recipient)
	binary.BigEndian.PutUint32(p[5:9], sender)
	binary.BigEndian.PutUint32(p[9:13], 0x100000)
	binary.BigEndian.PutUint32(p[13:17], 0x8000)
	return p
}

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

func TestEnvInjector_InjectsOncePerChannelOnFirstDownstreamPacket(t *testing.T) {
	var (
		mu       sync.Mutex
		injected [][]byte
	)
	writer := func(p []byte) error {
		mu.Lock()
		defer mu.Unlock()
		injected = append(injected, append([]byte(nil), p...))
		return nil
	}

	inj := &envInjector{
		writeUpstream: writer,
		env:           map[string]string{"FOO": "bar", "BAZ": "qux"},
	}

	// Step 1: upstream confirms channel-open with server-side id 7.
	if m, _, err := inj.up(openConfirmPkt(1, 7)); err != nil || m != ssh.PipePacketHookTransform {
		t.Fatalf("up: method=%v err=%v", m, err)
	}
	mu.Lock()
	if got := len(injected); got != 0 {
		t.Fatalf("env should not be injected at open-confirm time, got %d packets", got)
	}
	mu.Unlock()

	// Step 2: downstream sends first packet for channel 7 (e.g. data).
	out, _, err := func() (ssh.PipePacketHookMethod, []byte, error) {
		m, p, e := inj.down(channelDataPkt(7, []byte("ping")))
		return m, p, e
	}()
	if err != nil || out != ssh.PipePacketHookTransform {
		t.Fatalf("down: method=%v err=%v", out, err)
	}

	mu.Lock()
	gotPkts := injected
	mu.Unlock()
	if len(gotPkts) != 2 {
		t.Fatalf("expected 2 injected env packets, got %d", len(gotPkts))
	}
	for _, p := range gotPkts {
		if p[0] != msgChannelRequest {
			t.Errorf("injected packet first byte = %d, want %d", p[0], msgChannelRequest)
		}
		if cid := binary.BigEndian.Uint32(p[1:5]); cid != 7 {
			t.Errorf("injected packet channel id = %d, want 7", cid)
		}
	}

	// Step 3: a second downstream packet for the same channel must NOT
	// trigger re-injection.
	if _, _, err := inj.down(channelDataPkt(7, []byte("pong"))); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if got := len(injected); got != 2 {
		t.Errorf("second downstream packet should not re-inject; got %d total", got)
	}
	mu.Unlock()
}

func TestEnvInjector_SkipsUnknownChannels(t *testing.T) {
	called := false
	writer := func(p []byte) error { called = true; return nil }
	inj := &envInjector{
		writeUpstream: writer,
		env:           map[string]string{"FOO": "bar"},
	}

	// Downstream packet for an unconfirmed channel: must not inject.
	if _, _, err := inj.down(channelDataPkt(9, []byte("x"))); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("env injected for an unconfirmed channel")
	}
}

func TestEnvInjector_PerChannelIsolation(t *testing.T) {
	var (
		mu         sync.Mutex
		writeCount int
	)
	writer := func(p []byte) error { mu.Lock(); writeCount++; mu.Unlock(); return nil }
	inj := &envInjector{
		writeUpstream: writer,
		env:           map[string]string{"FOO": "bar"},
	}

	inj.up(openConfirmPkt(1, 7))
	inj.up(openConfirmPkt(2, 8))
	inj.down(channelDataPkt(7, nil)) // +1
	inj.down(channelDataPkt(7, nil)) // no change
	inj.down(channelDataPkt(8, nil)) // +1

	mu.Lock()
	defer mu.Unlock()
	if writeCount != 2 {
		t.Errorf("expected 2 injections (one per channel), got %d", writeCount)
	}
}
