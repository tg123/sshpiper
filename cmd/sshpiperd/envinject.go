package main

import (
	"encoding/binary"

	"golang.org/x/crypto/ssh"
)

// envInjector watches the downstream->upstream packet stream of a
// PiperConn and, immediately before each "shell" / "exec" / "subsystem"
// channel-request the client sends, writes one "env" channel-request
// per (key, value) pair to the upstream addressed to the same channel.
//
// Hooking on the terminal session-start request gives us natural
// per-channel scoping with zero session state:
//   - no dedup map (every channel gets exactly one batch, on its own
//     shell/exec/subsystem)
//   - no close tracking, no channel-id reuse pitfalls
//   - correct ordering per RFC 4254 §6.4: env requests are valid any
//     time before shell/exec, and arrive just before
//   - non-session channels (direct-tcpip etc.) never carry shell/exec
//     so they are naturally skipped
//
// PiperConn.WriteUpstreamPacket is safe to call from inside the
// downhook because the downhook goroutine is the sole upstream writer.
type envInjector struct {
	writeUpstream func([]byte) error
	env           map[string]string
}

func newEnvInjector(piper *ssh.PiperConn, env map[string]string) *envInjector {
	return &envInjector{
		writeUpstream: piper.WriteUpstreamPacket,
		env:           env,
	}
}

// down handles packets travelling downstream->upstream. On each
// SSH_MSG_CHANNEL_REQUEST whose request-type is "shell", "exec" or
// "subsystem", it writes one env channel-request per entry in e.env
// addressed to that channel before forwarding the original packet.
func (e *envInjector) down(pkt []byte) (ssh.PipePacketHookMethod, []byte, error) {
	if len(pkt) < 9 || pkt[0] != msgChannelRequest {
		return ssh.PipePacketHookTransform, pkt, nil
	}
	reqLen := binary.BigEndian.Uint32(pkt[5:9])
	if uint64(reqLen) > uint64(len(pkt)-9) {
		return ssh.PipePacketHookTransform, pkt, nil
	}
	switch string(pkt[9 : 9+reqLen]) {
	case "shell", "exec", "subsystem":
	default:
		return ssh.PipePacketHookTransform, pkt, nil
	}

	chID := binary.BigEndian.Uint32(pkt[1:5])
	for k, v := range e.env {
		envPkt := ssh.Marshal(envChannelRequest{
			PeersID:   chID,
			Request:   "env",
			WantReply: false,
			Name:      k,
			Value:     v,
		})
		if err := e.writeUpstream(envPkt); err != nil {
			return ssh.PipePacketHookTransform, pkt, err
		}
	}
	return ssh.PipePacketHookTransform, pkt, nil
}

// envChannelRequest is the wire encoding of an "env" channel-request
// packet (RFC 4254 §5.4 + §6.4). The sshtype:"98" tag tells ssh.Marshal
// to emit byte 98 (SSH_MSG_CHANNEL_REQUEST) as the first byte.
type envChannelRequest struct {
	PeersID   uint32 `sshtype:"98"`
	Request   string
	WantReply bool
	Name      string
	Value     string
}
