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

	// Bound reply-order bookkeeping to 1 KiB if an upstream never replies,
	// while allowing up to 1024 outstanding requests for pipelined clients.
	maxPendingGlobalReplies = 1024
)

// typePolicyFilter blocks downstream channel open and global requests
// whose type is rejected by the configured policies.
//
// Global requests (SSH_MSG_GLOBAL_REQUEST) are replied to with
// SSH_MSG_REQUEST_SUCCESS/FAILURE, neither of which carries a request ID:
// RFC 4254 §4 requires replies to be delivered in request order. pending
// tracks forwarded requests (false) and locally denied requests (true).
// down queues a denial behind unanswered requests without waiting, so it
// can keep reading other traffic and detect downstream EOF. up writes each
// genuine reply followed by any immediately following queued denials while
// holding mu. Only when the queue is empty may down return an immediate
// failure: it is written before that same goroutine forwards another request.
type typePolicyFilter struct {
	// channels/globalRequests are allow/deny lists over downstream channel
	// open types and global request types. A nil policy allows everything;
	// see typePolicy.
	channels       *typePolicy
	globalRequests *typePolicy

	// writeDownstream sends a packet to the downstream client from inside
	// the up hook (ssh.PiperConn.WriteDownstreamPacket in production), so
	// that up can write a genuine reply before queued local failures.
	// Must not be nil.
	writeDownstream func([]byte) error

	mu      sync.Mutex
	pending [maxPendingGlobalReplies]bool
	head    int
	count   int
	closed  bool
}

// newTypePolicyFilter creates a typePolicyFilter ready to be wired into a
// pipe's up/down hook chains. writeDownstream writes a packet to the
// downstream client and is only called from the up hook.
func newTypePolicyFilter(writeDownstream func([]byte) error, channels, globalRequests *typePolicy) *typePolicyFilter {
	return &typePolicyFilter{
		channels:        channels,
		globalRequests:  globalRequests,
		writeDownstream: writeDownstream,
	}
}

// close discards pending replies when either side of the pipe exits.
func (f *typePolicyFilter) close() {
	f.mu.Lock()
	f.closeLocked()
	f.mu.Unlock()
}

func (f *typePolicyFilter) closeLocked() {
	f.closed = true
	clear(f.pending[:])
	f.head = 0
	f.count = 0
}

func (f *typePolicyFilter) popReply() {
	f.pending[f.head] = false
	f.head = (f.head + 1) % len(f.pending)
	f.count--
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
		if f.globalRequests.empty() {
			return ssh.PipePacketHookTransform, packet, nil
		}

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

		f.mu.Lock()
		defer f.mu.Unlock()
		if f.closed {
			return ssh.PipePacketHookTransform, nil, net.ErrClosed
		}

		if blocked && f.count == 0 {
			return ssh.PipePacketHookReply, ssh.Marshal(globalRequestFailure{}), nil
		}
		if f.count == len(f.pending) {
			f.closeLocked()
			return ssh.PipePacketHookTransform, nil, fmt.Errorf("too many pending global request replies (limit %d)", maxPendingGlobalReplies)
		}
		f.pending[(f.head+f.count)%len(f.pending)] = blocked
		f.count++

		if blocked {
			return ssh.PipePacketHookTransform, nil, nil
		}
		return ssh.PipePacketHookTransform, packet, nil

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

// up writes global replies itself so queued denials cannot overtake the
// genuine upstream reply. Install it only when a global policy is configured.
func (f *typePolicyFilter) up(packet []byte) (ssh.PipePacketHookMethod, []byte, error) {
	if len(packet) > 0 && (packet[0] == msgRequestSuccess || packet[0] == msgRequestFailure) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.closed {
			return ssh.PipePacketHookTransform, nil, net.ErrClosed
		}

		if err := f.writeDownstream(packet); err != nil {
			f.closeLocked()
			return ssh.PipePacketHookTransform, nil, err
		}

		if f.count > 0 {
			f.popReply()
		}
		for f.count > 0 && f.pending[f.head] {
			if err := f.writeDownstream(ssh.Marshal(globalRequestFailure{})); err != nil {
				f.closeLocked()
				return ssh.PipePacketHookTransform, nil, err
			}
			f.popReply()
		}

		return ssh.PipePacketHookTransform, nil, nil
	}

	return ssh.PipePacketHookTransform, packet, nil
}
