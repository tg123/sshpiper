package main

import (
	"encoding/binary"

	"golang.org/x/crypto/ssh"
)

// SSH message types used for env-injection (RFC 4254 §5.1, §6.4).
// msg 93..100 are the channel-scoped messages a client may send after
// receiving an open-confirmation. msgChannelRequest is reused for the
// synthesised "env" request packets.
const (
	msgChannelWindowAdjust = 93
	msgChannelFailure      = 100
)

// envInjector watches the downstream->upstream packet stream of a
// PiperConn and, on the first channel-scoped packet a client sends for
// a given session channel, injects one "env" channel-request per
// (key, value) pair before forwarding the original packet. The env
// packets go to the upstream out-of-band via PiperConn.WriteUpstreamPacket,
// which is safe to call from inside the downhook (same goroutine that
// otherwise writes to upstream — naturally serialized).
//
// Per RFC 4254 a client can only emit channel-scoped messages
// (msg 93..100: window-adjust, data, extended-data, EOF, close, request,
// success, failure) after it has received an open-confirmation. Seeing
// such a message therefore implies the channel is already confirmed and
// pkt[1:5] is the server-side recipient channel id we must address.
// That makes cross-goroutine state (and any mutex) unnecessary: only
// the down hook touches envInjector.
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
// channel-scoped packet for each channel it writes one env
// channel-request per entry in e.env to the upstream, then forwards the
// original packet unchanged.
func (e *envInjector) down(pkt []byte) (ssh.PipePacketHookMethod, []byte, error) {
	if len(pkt) < 5 {
		return ssh.PipePacketHookTransform, pkt, nil
	}
	// Only msg 93..100 carry recipient channel id at pkt[1:5]. msg 90
	// (channel-open) carries the sender's own id there, and other
	// message types are not channel-scoped at all.
	if pkt[0] < msgChannelWindowAdjust || pkt[0] > msgChannelFailure {
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
