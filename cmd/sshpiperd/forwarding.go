package main

import (
	"sync"

	"golang.org/x/crypto/ssh"
)

const (
	msgGlobalRequest     = 80
	msgRequestSuccess    = 81
	msgRequestFailure    = 82
	msgChannelOpen       = 90
	msgChannelOpenFailed = 92

	connectionFailedAdministratively = 1
)

// forwardingFilter blocks local/remote port-forwarding requests on the
// downstream->upstream stream.
//
// Global requests (SSH_MSG_GLOBAL_REQUEST) are replied to with
// SSH_MSG_REQUEST_SUCCESS/FAILURE, neither of which carries a request ID:
// RFC 4254 §4 requires replies to be delivered in the same order requests
// were sent. When a remote-forward request is blocked, down answers it
// immediately itself instead of forwarding it upstream, so that immediate
// local reply could otherwise race ahead of - and be delivered out of order
// with - the genuine upstream reply to an earlier, unblocked, want-reply
// global request (the two are written to the downstream connection from
// different goroutines: down's own hook, and the up hook piping upstream's
// replies back).
//
// seq/replied/cond track how many want-reply global requests have been
// seen (in down) and answered (in up, for forwarded ones, or in down
// itself, for blocked ones) so that down can block a locally-generated
// failure until every earlier request has already been replied to.
type forwardingFilter struct {
	disableLocal  bool
	disableRemote bool

	mu      sync.Mutex
	cond    *sync.Cond
	seq     int
	replied int
}

// newForwardingFilter creates a forwardingFilter ready to be wired into a
// pipe's up/down hook chains.
func newForwardingFilter(disableLocal, disableRemote bool) *forwardingFilter {
	f := &forwardingFilter{
		disableLocal:  disableLocal,
		disableRemote: disableRemote,
	}
	f.cond = sync.NewCond(&f.mu)
	return f
}

type globalRequest struct {
	Type      string `sshtype:"80"`
	WantReply bool
	Data      []byte `ssh:"rest"`
}

type globalRequestFailure struct {
	Data []byte `ssh:"rest" sshtype:"82"`
}

type channelOpen struct {
	Type             string `sshtype:"90"`
	SenderChannel    uint32
	InitialWindow    uint32
	MaximumPacket    uint32
	TypeSpecificData []byte `ssh:"rest"`
}

type channelOpenFailure struct {
	RecipientChannel uint32 `sshtype:"92"`
	ReasonCode       uint32
	Description      string
	Language         string
}

// isRemoteForwardRequestType reports whether the global request type establishes
// or cancels remote (ssh -R) port forwarding. This covers both TCP forwarding
// (tcpip-forward) and OpenSSH's Unix-domain socket forwarding
// (streamlocal-forward@openssh.com), along with their cancel counterparts.
func isRemoteForwardRequestType(t string) bool {
	switch t {
	case "tcpip-forward", "cancel-tcpip-forward",
		"streamlocal-forward@openssh.com", "cancel-streamlocal-forward@openssh.com":
		return true
	default:
		return false
	}
}

// isLocalForwardChannelType reports whether the channel open type establishes
// local (ssh -L) forwarding. This covers both TCP destinations (direct-tcpip)
// and OpenSSH's Unix-domain socket destinations
// (direct-streamlocal@openssh.com).
func isLocalForwardChannelType(t string) bool {
	switch t {
	case "direct-tcpip", "direct-streamlocal@openssh.com":
		return true
	default:
		return false
	}
}

func (f *forwardingFilter) down(packet []byte) (ssh.PipePacketHookMethod, []byte, error) {
	if len(packet) == 0 {
		return ssh.PipePacketHookTransform, packet, nil
	}

	switch packet[0] {
	case msgGlobalRequest:
		var request globalRequest
		if err := ssh.Unmarshal(packet, &request); err != nil {
			return ssh.PipePacketHookTransform, packet, nil
		}

		blocked := f.disableRemote && isRemoteForwardRequestType(request.Type)

		if !request.WantReply {
			if blocked {
				return ssh.PipePacketHookTransform, nil, nil
			}
			return ssh.PipePacketHookTransform, packet, nil
		}

		// Reserve our place in the reply order before deciding how to
		// answer: every want-reply global request - blocked or not -
		// occupies a slot that must be filled, in order, by exactly one
		// reply sent back to the downstream client.
		f.mu.Lock()
		mySeq := f.seq
		f.seq++
		f.mu.Unlock()

		if !blocked {
			return ssh.PipePacketHookTransform, packet, nil
		}

		// Wait until every earlier want-reply global request has already
		// been replied to (by up, for ones forwarded upstream) before
		// sending our own locally-generated failure, so replies reach the
		// client in the same order the requests were sent.
		f.mu.Lock()
		for f.replied < mySeq {
			f.cond.Wait()
		}
		f.replied++
		f.cond.Broadcast()
		f.mu.Unlock()

		return ssh.PipePacketHookReply, ssh.Marshal(globalRequestFailure{}), nil

	case msgChannelOpen:
		var open channelOpen
		if err := ssh.Unmarshal(packet, &open); err != nil {
			return ssh.PipePacketHookTransform, packet, nil
		}
		if !f.disableLocal || !isLocalForwardChannelType(open.Type) {
			return ssh.PipePacketHookTransform, packet, nil
		}
		return ssh.PipePacketHookReply, ssh.Marshal(channelOpenFailure{
			RecipientChannel: open.SenderChannel,
			ReasonCode:       connectionFailedAdministratively,
			Description:      "port forwarding is disabled",
		}), nil
	}

	return ssh.PipePacketHookTransform, packet, nil
}

// up handles packets travelling upstream->downstream. It only needs to
// watch for SSH_MSG_REQUEST_SUCCESS/FAILURE (global request replies): each
// one is the genuine upstream reply to a want-reply global request that
// down forwarded (unblocked) rather than answering itself. Recording it
// here lets a later, blocked, want-reply request's locally-generated
// failure in down proceed only once every earlier reply has already gone
// out, preserving the client-observed reply order. up must only be
// installed when disableRemote is set, since that is the only case where
// down can generate a reply of its own that needs to be sequenced against
// genuine upstream replies.
func (f *forwardingFilter) up(packet []byte) (ssh.PipePacketHookMethod, []byte, error) {
	if len(packet) > 0 && (packet[0] == msgRequestSuccess || packet[0] == msgRequestFailure) {
		f.mu.Lock()
		f.replied++
		f.cond.Broadcast()
		f.mu.Unlock()
	}

	return ssh.PipePacketHookTransform, packet, nil
}
