package main

import (
	"fmt"
	"net"
	"strings"
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

// typePolicyFilter blocks downstream channel open and global requests
// whose type is rejected by the configured policies.
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
// failure until every earlier request has already been replied to. up
// counts a forwarded request as replied only after it has written the
// genuine upstream reply downstream itself, so a released local failure
// can neither overtake it nor be written concurrently with it.
type typePolicyFilter struct {
	// channels/globalRequests are allow/deny lists over downstream channel
	// open types and global request types. A nil policy allows everything;
	// see typePolicy.
	channels       *typePolicy
	globalRequests *typePolicy

	// writeDownstream sends a packet to the downstream client from inside
	// the up hook (ssh.PiperConn.WriteDownstreamPacket in production), so
	// that up can write a genuine upstream reply itself and only then
	// release a waiter in down. Must not be nil.
	writeDownstream func([]byte) error

	mu      sync.Mutex
	cond    *sync.Cond
	seq     int
	replied int
	closed  bool
}

// newTypePolicyFilter creates a typePolicyFilter ready to be wired into a
// pipe's up/down hook chains. writeDownstream writes a packet to the
// downstream client and is only called from the up hook.
func newTypePolicyFilter(writeDownstream func([]byte) error, channels, globalRequests *typePolicy) *typePolicyFilter {
	f := &typePolicyFilter{
		channels:        channels,
		globalRequests:  globalRequests,
		writeDownstream: writeDownstream,
	}
	f.cond = sync.NewCond(&f.mu)
	return f
}

// close releases reply-order waiters when either side of the pipe exits.
func (f *typePolicyFilter) close() {
	f.mu.Lock()
	f.closed = true
	f.cond.Broadcast()
	f.mu.Unlock()
}

// typePolicy is an allow/deny list over SSH type names (channel types for
// SSH_MSG_CHANNEL_OPEN, request names for SSH_MSG_GLOBAL_REQUEST).
//
// Exactly one of the two lists may be configured:
//   - allow set: only the listed types are permitted, everything else -
//     including types added by future protocol extensions - is rejected.
//   - deny set: the listed types are rejected, everything else is permitted.
//
// A nil *typePolicy permits everything.
type typePolicy struct {
	allow map[string]struct{}
	deny  map[string]struct{}

	// isAllow selects which list is in effect. An allow-list policy stays in
	// effect even when allow ends up empty (which then rejects everything),
	// so it must not be inferred from the map lengths.
	isAllow bool
}

// newTypePolicy builds a typePolicy from the raw allowed/denied flag values.
// kind is only used to render the error message when both lists are set.
//
// alwaysDenied holds types denied by convenience switches such as
// --disable-remote-forwarding: they are merged into the resulting policy so
// that every rejection goes through the same code path. Merging into an
// allow list means removing those types from it, since an allow list only
// permits what it names.
func newTypePolicy(kind string, allowed, denied, alwaysDenied []string) (*typePolicy, error) {
	if len(allowed) > 0 && len(denied) > 0 {
		return nil, fmt.Errorf("--allowed-%v and --denied-%v are mutually exclusive, set only one", kind, kind)
	}

	allow := parseTypeList(allowed)
	deny := parseTypeList(denied)
	sugar := parseTypeList(alwaysDenied)

	if len(allow) > 0 {
		for t := range sugar {
			delete(allow, t)
		}
		return &typePolicy{allow: allow, isAllow: true}, nil
	}

	for t := range sugar {
		if deny == nil {
			deny = make(map[string]struct{}, len(sugar))
		}
		deny[t] = struct{}{}
	}

	if len(deny) == 0 {
		return nil, nil
	}

	return &typePolicy{deny: deny}, nil
}

// parseTypeList normalizes a repeatable/comma-separated flag value into a
// set, dropping surrounding whitespace and empty entries. Type names are
// matched case-sensitively, as required by RFC 4250 §4.6.
func parseTypeList(values []string) map[string]struct{} {
	var set map[string]struct{}

	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if set == nil {
			set = make(map[string]struct{})
		}
		set[v] = struct{}{}
	}

	return set
}

// empty reports whether the policy has no effect, i.e. it permits every type.
func (p *typePolicy) empty() bool {
	return p == nil || (!p.isAllow && len(p.deny) == 0)
}

// blocked reports whether t must be rejected under this policy.
func (p *typePolicy) blocked(t string) bool {
	if p == nil {
		return false
	}

	if p.isAllow {
		_, ok := p.allow[t]
		return !ok
	}

	_, ok := p.deny[t]
	return ok
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

// remoteForwardRequestTypes are the global request types that establish or
// cancel remote (ssh -R) port forwarding, denied by
// --disable-remote-forwarding. This covers both TCP forwarding
// (tcpip-forward) and OpenSSH's Unix-domain socket forwarding
// (streamlocal-forward@openssh.com), along with their cancel counterparts.
var remoteForwardRequestTypes = []string{
	"tcpip-forward", "cancel-tcpip-forward",
	"streamlocal-forward@openssh.com", "cancel-streamlocal-forward@openssh.com",
}

// localForwardChannelTypes are the channel open types that establish local
// (ssh -L) or dynamic (ssh -D) forwarding, denied by
// --disable-local-forwarding. This covers both TCP destinations
// (direct-tcpip) and OpenSSH's Unix-domain socket destinations
// (direct-streamlocal@openssh.com).
var localForwardChannelTypes = []string{
	"direct-tcpip", "direct-streamlocal@openssh.com",
}

func (f *typePolicyFilter) down(packet []byte) (ssh.PipePacketHookMethod, []byte, error) {
	if len(packet) == 0 {
		return ssh.PipePacketHookTransform, packet, nil
	}

	switch packet[0] {
	case msgGlobalRequest:
		var request globalRequest
		if err := ssh.Unmarshal(packet, &request); err != nil {
			return ssh.PipePacketHookTransform, packet, nil
		}

		blocked := f.globalRequests.blocked(request.Type)

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
		for f.replied < mySeq && !f.closed {
			f.cond.Wait()
		}
		if f.closed {
			f.mu.Unlock()
			return ssh.PipePacketHookTransform, nil, net.ErrClosed
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
		if f.channels.blocked(open.Type) {
			return ssh.PipePacketHookReply, ssh.Marshal(channelOpenFailure{
				RecipientChannel: open.SenderChannel,
				ReasonCode:       connectionFailedAdministratively,
				Description:      "channel type is not allowed",
			}), nil
		}
		return ssh.PipePacketHookTransform, packet, nil
	}

	return ssh.PipePacketHookTransform, packet, nil
}

// up handles packets travelling upstream->downstream. It only needs to
// watch for SSH_MSG_REQUEST_SUCCESS/FAILURE (global request replies): each
// one is the genuine upstream reply to a want-reply global request that
// down forwarded (unblocked) rather than answering itself. Such a reply is
// written downstream here, by up itself, and the original packet is then
// dropped: recording it as replied only after the write has completed is
// what makes a later, blocked, want-reply request's locally-generated
// failure in down land behind it, preserving the client-observed reply
// order. Letting the piping loop do the write instead would release the
// waiter in down while the genuine reply is still unwritten, so the local
// failure could overtake it. up must only be installed when down can
// generate a reply of its own that needs to be sequenced against genuine
// upstream replies, i.e. when a global request policy is configured.
func (f *typePolicyFilter) up(packet []byte) (ssh.PipePacketHookMethod, []byte, error) {
	if len(packet) > 0 && (packet[0] == msgRequestSuccess || packet[0] == msgRequestFailure) {
		if err := f.writeDownstream(packet); err != nil {
			f.close()
			return ssh.PipePacketHookTransform, nil, err
		}

		f.mu.Lock()
		f.replied++
		f.cond.Broadcast()
		f.mu.Unlock()

		return ssh.PipePacketHookTransform, nil, nil
	}

	return ssh.PipePacketHookTransform, packet, nil
}
