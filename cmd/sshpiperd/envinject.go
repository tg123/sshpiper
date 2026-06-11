package main

import (
	"encoding/binary"

	"golang.org/x/crypto/ssh"
)

// SSH message type used to recognise a session channel-request
// (RFC 4254 §5.4). Only msg 98 packets are inspected; injecting on the
// first channel-request for a given channel matches what real SSH
// clients do (pty-req / env / shell / exec / subsystem are all carried
// in msg 98). Non-session channels (e.g. direct-tcpip port forwards)
// don't emit channel-requests in normal use, so this naturally scopes
// injection to session channels.

// envInjector watches the downstream->upstream packet stream of a
// PiperConn and, on the first SSH_MSG_CHANNEL_REQUEST a client sends
// for a given channel, injects one "env" channel-request per
// (key, value) pair before forwarding the original packet. The env
// packets go to the upstream out-of-band via PiperConn.WriteUpstreamPacket,
// which is safe to call from inside the downhook (same goroutine that
// otherwise writes to upstream — naturally serialized).
//
// Per RFC 4254 a client can only emit channel-scoped messages after it
// has received an open-confirmation, so seeing a msg 98 from downstream
// implies the channel is already confirmed and pkt[1:5] is the
// server-side recipient channel id we must address. That makes
// cross-goroutine state (and any mutex) unnecessary: only the down hook
// touches envInjector.
type envInjector struct {
	writeUpstream func([]byte) error
	env           map[string]string
	injected      map[uint32]bool
}

func newEnvInjector(piper *ssh.PiperConn, env map[string]string) *envInjector {
	return &envInjector{
		writeUpstream: piper.WriteUpstreamPacket,
		env:           env,
		injected:      make(map[uint32]bool),
	}
}

// down handles packets travelling downstream->upstream. On the first
// SSH_MSG_CHANNEL_REQUEST it sees for each channel it writes one env
// channel-request per entry in e.env to the upstream, then forwards the
// original packet unchanged.
func (e *envInjector) down(pkt []byte) (ssh.PipePacketHookMethod, []byte, error) {
	if len(pkt) < 5 || pkt[0] != msgChannelRequest {
		return ssh.PipePacketHookTransform, pkt, nil
	}
	chID := binary.BigEndian.Uint32(pkt[1:5])
	if e.injected[chID] {
		return ssh.PipePacketHookTransform, pkt, nil
	}
	e.injected[chID] = true

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
