package main

import (
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/ssh"
)

// helper: construct a channel-request packet (msg 98) addressed to
// channelID carrying request-type req. want_reply=false, no payload.
func channelRequestPkt(channelID uint32, req string) []byte {
	p := make([]byte, 1+4+4+len(req)+1)
	p[0] = msgChannelRequest
	binary.BigEndian.PutUint32(p[1:5], channelID)
	binary.BigEndian.PutUint32(p[5:9], uint32(len(req)))
	copy(p[9:], req)
	return p
}

// helper: channel-data packet (msg 94) — must never trigger injection.
func channelDataPkt(channelID uint32, data []byte) []byte {
	p := make([]byte, 9+len(data))
	p[0] = 94
	binary.BigEndian.PutUint32(p[1:5], channelID)
	binary.BigEndian.PutUint32(p[5:9], uint32(len(data)))
	copy(p[9:], data)
	return p
}

func TestEnvInjector_InjectsOnShellExecSubsystem(t *testing.T) {
	for _, req := range []string{"shell", "exec", "subsystem"} {
		t.Run(req, func(t *testing.T) {
			var injected [][]byte
			inj := &envInjector{
				writeUpstream: func(p []byte) error {
					injected = append(injected, append([]byte(nil), p...))
					return nil
				},
				env: map[string]string{"FOO": "bar", "BAZ": "qux"},
			}

			if m, _, err := inj.down(channelRequestPkt(7, req)); err != nil || m != ssh.PipePacketHookTransform {
				t.Fatalf("down: method=%v err=%v", m, err)
			}
			if len(injected) != 2 {
				t.Fatalf("expected 2 env packets, got %d", len(injected))
			}
			for _, p := range injected {
				if p[0] != msgChannelRequest {
					t.Errorf("injected first byte = %d, want %d", p[0], msgChannelRequest)
				}
				if cid := binary.BigEndian.Uint32(p[1:5]); cid != 7 {
					t.Errorf("injected channel id = %d, want 7", cid)
				}
			}
		})
	}
}

func TestEnvInjector_SkipsNonSessionStartingRequests(t *testing.T) {
	for _, pkt := range [][]byte{
		channelRequestPkt(7, "pty-req"),
		channelRequestPkt(7, "env"),
		channelRequestPkt(7, "window-change"),
		channelRequestPkt(7, "signal"),
		channelDataPkt(7, []byte("ping")),
	} {
		called := false
		inj := &envInjector{
			writeUpstream: func(p []byte) error { called = true; return nil },
			env:           map[string]string{"FOO": "bar"},
		}
		if _, _, err := inj.down(pkt); err != nil {
			t.Fatal(err)
		}
		if called {
			t.Errorf("env injected for pkt type %q", requestType(pkt))
		}
	}
}

func TestEnvInjector_InjectsPerChannelOnEachShellExec(t *testing.T) {
	writes := 0
	inj := &envInjector{
		writeUpstream: func(p []byte) error { writes++; return nil },
		env:           map[string]string{"FOO": "bar"},
	}

	for _, p := range [][]byte{
		channelRequestPkt(7, "shell"), // +1
		channelRequestPkt(8, "exec"),  // +1
		channelRequestPkt(9, "shell"), // +1
	} {
		if _, _, err := inj.down(p); err != nil {
			t.Fatal(err)
		}
	}
	if writes != 3 {
		t.Errorf("expected 3 injections (one per channel's shell/exec), got %d", writes)
	}
}

func TestEnvInjector_RejectsMalformedFraming(t *testing.T) {
	// Packet ends exactly after request-type string with no want_reply byte.
	const req = "shell"
	p := make([]byte, 1+4+4+len(req))
	p[0] = msgChannelRequest
	binary.BigEndian.PutUint32(p[1:5], 7)
	binary.BigEndian.PutUint32(p[5:9], uint32(len(req)))
	copy(p[9:], req)

	called := false
	inj := &envInjector{
		writeUpstream: func(_ []byte) error { called = true; return nil },
		env:           map[string]string{"FOO": "bar"},
	}
	if _, _, err := inj.down(p); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("env injected for malformed channel-request (missing want_reply byte)")
	}
}

// requestType pulls the request-type string out of a msg 98 packet for
// diagnostics; returns "" if pkt isn't a channel-request.
func requestType(pkt []byte) string {
	if len(pkt) < 9 || pkt[0] != msgChannelRequest {
		return ""
	}
	n := binary.BigEndian.Uint32(pkt[5:9])
	if uint64(n) > uint64(len(pkt)-9) {
		return ""
	}
	return string(pkt[9 : 9+n])
}
