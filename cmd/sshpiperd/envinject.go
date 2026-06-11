package main

import (
	"encoding/binary"
	"sync"

	"golang.org/x/crypto/ssh"
)

// SSH message types used for env injection. RFC 4254 §5.1, §6.4.
// (msgChannelRequest / msgChannelOpenConfirm are declared in asciicast.go.)

// envInjector watches the SSH packet stream of a PiperConn and, on each
// upstream-confirmed session channel, injects one "env" channel-request
// per (key, value) pair before the client's shell/exec/subsystem
// request. Hooks here are plain PipePacketHooks (single packet in,
// single packet out); the extra env packets are written to the
// upstream out-of-band via PiperConn.WriteUpstreamPacket, which is safe
// to call from inside a hook.
type envInjector struct {
	writeUpstream func([]byte) error
	env           map[string]string

	serverIDs sync.Map // set of confirmed server-side channel IDs (key: uint32)
	injected  sync.Map // set of channel IDs that have already had env injected (key: uint32)
}

func newEnvInjector(piper *ssh.PiperConn, env map[string]string) *envInjector {
	return &envInjector{
		writeUpstream: piper.WriteUpstreamPacket,
		env:           env,
	}
}

// up handles packets travelling upstream->downstream. It records the
// server-side ("sender") channel id from channel-open-confirmation
// packets so the down hook knows the correct recipient channel for
// synthetic env requests.
func (e *envInjector) up(pkt []byte) (ssh.PipePacketHookMethod, []byte, error) {
	if len(pkt) >= 9 && pkt[0] == msgChannelOpenConfirm {
		// channel-open-confirmation: recipient(4) sender(4) window(4) max(4)
		serverID := binary.BigEndian.Uint32(pkt[5:9])
		e.serverIDs.Store(serverID, struct{}{})
	}
	return ssh.PipePacketHookTransform, pkt, nil
}

// down handles packets travelling downstream->upstream. On the first
// packet for a confirmed server-side channel id it writes one env
// channel-request per entry in e.env to the upstream, then forwards
// the original packet unchanged.
func (e *envInjector) down(pkt []byte) (ssh.PipePacketHookMethod, []byte, error) {
	if len(pkt) < 5 {
		return ssh.PipePacketHookTransform, pkt, nil
	}
	chID := binary.BigEndian.Uint32(pkt[1:5])
	if _, confirmed := e.serverIDs.Load(chID); !confirmed {
		return ssh.PipePacketHookTransform, pkt, nil
	}
	if _, already := e.injected.LoadOrStore(chID, struct{}{}); already {
		return ssh.PipePacketHookTransform, pkt, nil
	}

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

// envChannelRequest is the wire encoding of a "env" channel-request
// packet (RFC 4254 §5.4 + §6.4). The sshtype:"98" tag tells ssh.Marshal
// to emit byte 98 (SSH_MSG_CHANNEL_REQUEST) as the first byte.
type envChannelRequest struct {
	PeersID   uint32 `sshtype:"98"`
	Request   string // "env"
	WantReply bool
	Name      string
	Value     string
}
