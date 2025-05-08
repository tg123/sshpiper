package main

import "golang.org/x/crypto/ssh"

type hookChain struct {
	hooks []ssh.PipePacketHook
}

// chain stops if any of the hooks return ssh.PipePacketHookReply
func (h *hookChain) append(hook ssh.PipePacketHook) {
	if hook != nil {
		h.hooks = append(h.hooks, hook)
	}
}

func (h *hookChain) hook() ssh.PipePacketHook {

	if len(h.hooks) == 0 {
		return nil
	}

	return func(packet []byte) (method ssh.PipePacketHookMethod, packetOut []byte, err error) {
		packetOut = packet
		for _, hk := range h.hooks {
			method, packetOut, err = hk(packetOut)
			if err != nil {
				return
			}

			if method == ssh.PipePacketHookReply {
				return
			}
		}

		return
	}
}
