package main

import (
	"time"

	"golang.org/x/crypto/ssh"
)

// newIdleTimeoutHook returns a PipePacketHook that resets timer whenever it
// sees an SSH channel-data packet (msg 94) or extended-channel-data packet
// (msg 95). Other messages (keepalives, window adjustments, etc.) are
// intentionally ignored so that periodic SSH keepalives do not defeat the
// inactivity detection. Returns nil if timeout <= 0.
func newIdleTimeoutHook(timer *time.Timer, timeout time.Duration) ssh.PipePacketHook {
	if timer == nil || timeout <= 0 {
		return nil
	}
	return func(packet []byte) (ssh.PipePacketHookMethod, []byte, error) {
		if len(packet) > 0 && (packet[0] == 94 || packet[0] == 95) {
			timer.Reset(timeout)
		}
		return ssh.PipePacketHookTransform, packet, nil
	}
}
