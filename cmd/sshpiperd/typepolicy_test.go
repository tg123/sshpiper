package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// disableLocalForwardPolicy / disableRemoteForwardPolicy build the policies
// that --disable-local-forwarding / --disable-remote-forwarding desugar to.
func disableLocalForwardPolicy(t *testing.T) *typePolicy {
	t.Helper()

	return mustTypePolicy(t, "channel-types", nil, nil, localForwardChannelTypes)
}

func disableRemoteForwardPolicy(t *testing.T) *typePolicy {
	t.Helper()

	return mustTypePolicy(t, "global-requests", nil, nil, remoteForwardRequestTypes)
}

// discardDownstream is a downstream writer for filters whose up hook does
// not need to be observed by the test.
func discardDownstream([]byte) error { return nil }

func TestTypePolicyFilterDisablesRemoteForwarding(t *testing.T) {
	filter := newTypePolicyFilter(discardDownstream, nil, disableRemoteForwardPolicy(t))

	for _, requestType := range []string{
		"tcpip-forward", "cancel-tcpip-forward",
		"streamlocal-forward@openssh.com", "cancel-streamlocal-forward@openssh.com",
	} {
		t.Run(requestType, func(t *testing.T) {
			packet := ssh.Marshal(globalRequest{Type: requestType, WantReply: true})
			method, reply, err := filter.down(packet)
			if err != nil {
				t.Fatal(err)
			}
			if method != ssh.PipePacketHookReply {
				t.Fatalf("method = %v, want PipePacketHookReply", method)
			}
			if !bytes.Equal(reply, []byte{msgRequestFailure}) {
				t.Fatalf("reply = %v, want SSH_MSG_REQUEST_FAILURE", reply)
			}
		})
	}
}

func TestTypePolicyFilterDropsRemoteForwardingWithoutReply(t *testing.T) {
	filter := newTypePolicyFilter(discardDownstream, nil, disableRemoteForwardPolicy(t))
	packet := ssh.Marshal(globalRequest{Type: "tcpip-forward", WantReply: false})

	method, reply, err := filter.down(packet)
	if err != nil {
		t.Fatal(err)
	}
	if method != ssh.PipePacketHookTransform {
		t.Fatalf("method = %v, want PipePacketHookTransform", method)
	}
	if reply != nil {
		t.Fatalf("reply = %v, want nil", reply)
	}
}

func TestTypePolicyFilterDisablesLocalForwarding(t *testing.T) {
	filter := newTypePolicyFilter(discardDownstream, disableLocalForwardPolicy(t), nil)

	for _, channelType := range []string{"direct-tcpip", "direct-streamlocal@openssh.com"} {
		t.Run(channelType, func(t *testing.T) {
			packet := ssh.Marshal(channelOpen{Type: channelType, SenderChannel: 42})

			method, reply, err := filter.down(packet)
			if err != nil {
				t.Fatal(err)
			}
			if method != ssh.PipePacketHookReply {
				t.Fatalf("method = %v, want PipePacketHookReply", method)
			}

			var failure channelOpenFailure
			if err := ssh.Unmarshal(reply, &failure); err != nil {
				t.Fatal(err)
			}
			if reply[0] != msgChannelOpenFailed {
				t.Fatalf("message type = %d, want %d", reply[0], msgChannelOpenFailed)
			}
			if failure.RecipientChannel != 42 {
				t.Fatalf("recipient channel = %d, want 42", failure.RecipientChannel)
			}
			if failure.ReasonCode != connectionFailedAdministratively {
				t.Fatalf("reason code = %d, want %d", failure.ReasonCode, connectionFailedAdministratively)
			}
		})
	}
}

func TestTypePolicyFilterAllowsUnblockedRequests(t *testing.T) {
	tests := []struct {
		name   string
		filter *typePolicyFilter
		packet []byte
	}{
		{
			name:   "remote forwarding enabled",
			filter: newTypePolicyFilter(discardDownstream, nil, nil),
			packet: ssh.Marshal(globalRequest{Type: "tcpip-forward", WantReply: true}),
		},
		{
			name:   "unrelated global request",
			filter: newTypePolicyFilter(discardDownstream, nil, disableRemoteForwardPolicy(t)),
			packet: ssh.Marshal(globalRequest{Type: "keepalive@openssh.com", WantReply: true}),
		},
		{
			name:   "local forwarding enabled",
			filter: newTypePolicyFilter(discardDownstream, nil, nil),
			packet: ssh.Marshal(channelOpen{Type: "direct-tcpip", SenderChannel: 42}),
		},
		{
			name:   "session channel",
			filter: newTypePolicyFilter(discardDownstream, disableLocalForwardPolicy(t), nil),
			packet: ssh.Marshal(channelOpen{Type: "session", SenderChannel: 42}),
		},
		{
			name:   "unrelated packet",
			filter: newTypePolicyFilter(discardDownstream, disableLocalForwardPolicy(t), disableRemoteForwardPolicy(t)),
			packet: []byte{msgChannelRequest},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, packet, err := tt.filter.down(tt.packet)
			if err != nil {
				t.Fatal(err)
			}
			if method != ssh.PipePacketHookTransform {
				t.Fatalf("method = %v, want PipePacketHookTransform", method)
			}
			if !bytes.Equal(packet, tt.packet) {
				t.Fatalf("packet = %v, want unchanged %v", packet, tt.packet)
			}
		})
	}
}

func TestTypePolicyFilterAllowsMalformedRequests(t *testing.T) {
	filter := newTypePolicyFilter(discardDownstream, disableLocalForwardPolicy(t), disableRemoteForwardPolicy(t))

	for _, packet := range [][]byte{
		nil,
		{msgGlobalRequest},
		{msgChannelOpen},
	} {
		method, output, err := filter.down(packet)
		if err != nil {
			t.Fatal(err)
		}
		if method != ssh.PipePacketHookTransform {
			t.Fatalf("method = %v, want PipePacketHookTransform", method)
		}
		if !bytes.Equal(output, packet) {
			t.Fatalf("packet = %v, want unchanged %v", output, packet)
		}
	}
}

func TestTypePolicyFilterPreservesGlobalRequestReplyOrder(t *testing.T) {
	var written [][]byte
	filter := newTypePolicyFilter(func(pkt []byte) error {
		written = append(written, bytes.Clone(pkt))
		return nil
	}, nil, disableRemoteForwardPolicy(t))

	down := func(blocked, wantReply bool) {
		t.Helper()
		requestType := "keepalive@openssh.com"
		if blocked {
			requestType = "tcpip-forward"
		}
		packet := ssh.Marshal(globalRequest{Type: requestType, WantReply: wantReply})
		method, out, err := filter.down(packet)
		if err != nil || method != ssh.PipePacketHookTransform {
			t.Fatalf("down = %v, %v, %v, want Transform without error", method, out, err)
		}
		if blocked && out != nil {
			t.Fatalf("blocked packet = %v, want nil", out)
		}
		if !blocked && !bytes.Equal(out, packet) {
			t.Fatalf("allowed packet = %v, want %v", out, packet)
		}
	}
	up := func(packet []byte, want ...[]byte) {
		t.Helper()
		written = nil
		method, out, err := filter.up(packet)
		if err != nil || method != ssh.PipePacketHookTransform || out != nil {
			t.Fatalf("up = %v, %v, %v, want Transform, nil, nil", method, out, err)
		}
		if len(written) != len(want) {
			t.Fatalf("writes = %v, want %v", written, want)
		}
		for i := range want {
			if !bytes.Equal(written[i], want[i]) {
				t.Fatalf("write %d = %v, want %v", i, written[i], want[i])
			}
		}
	}

	down(false, true) // A
	down(false, true) // B
	down(true, false)
	down(true, true) // C
	down(true, true) // D
	down(false, false)
	down(false, true) // E
	down(true, true)  // F
	if len(written) != 0 || filter.count != 6 {
		t.Fatalf("writes, pending = %v, %v, want none, 6", written, filter.count)
	}

	successA := []byte{msgRequestSuccess, 0, 0, 0, 42}
	successE := []byte{msgRequestSuccess, 0, 0, 0, 43}
	failure := []byte{msgRequestFailure}
	up(successA, successA)
	up(failure, failure, failure, failure)   // B, C, D
	down(true, true)                         // G
	up(successE, successE, failure, failure) // E, F, G
	if filter.count != 0 {
		t.Fatalf("pending = %v, want 0", filter.count)
	}
	method, reply, err := filter.down(ssh.Marshal(globalRequest{Type: "tcpip-forward", WantReply: true}))
	if err != nil || method != ssh.PipePacketHookReply || !bytes.Equal(reply, failure) {
		t.Fatalf("immediate denial = %v, %v, %v", method, reply, err)
	}
}

func TestTypePolicyFilterSerializesInFlightReply(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var written []byte
	filter := newTypePolicyFilter(func(packet []byte) error {
		close(started)
		<-release
		written = append(written, packet...)
		return nil
	}, nil, disableRemoteForwardPolicy(t))
	if _, _, err := filter.down(ssh.Marshal(globalRequest{Type: "keepalive@openssh.com", WantReply: true})); err != nil {
		t.Fatal(err)
	}
	go func() {
		if _, _, err := filter.up([]byte{msgRequestSuccess}); err != nil {
			t.Error(err)
		}
	}()
	<-started

	done := make(chan struct{})
	go func() {
		defer close(done)
		method, reply, err := filter.down(ssh.Marshal(globalRequest{Type: "tcpip-forward", WantReply: true}))
		if err != nil || method != ssh.PipePacketHookReply {
			t.Errorf("down = %v, %v, %v", method, reply, err)
		}
		written = append(written, reply...)
	}()
	select {
	case <-done:
		t.Error("local failure overtook the in-flight upstream write")
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	waitDone(t, done)
	if !bytes.Equal(written, []byte{msgRequestSuccess, msgRequestFailure}) {
		t.Fatalf("writes = %v, want success then failure", written)
	}
}

func TestTypePolicyFilterWriteErrorClearsPendingReplies(t *testing.T) {
	for _, replyType := range []byte{msgRequestSuccess, msgRequestFailure} {
		for _, failAt := range []int{1, 2, 3} {
			t.Run(fmt.Sprintf("reply=%d/failAt=%d", replyType, failAt), func(t *testing.T) {
				want := errors.New("write failed")
				writes := 0
				filter := newTypePolicyFilter(func([]byte) error {
					writes++
					if writes == failAt {
						return want
					}
					return nil
				}, nil, disableRemoteForwardPolicy(t))
				for _, requestType := range []string{"keepalive@openssh.com", "tcpip-forward", "tcpip-forward"} {
					if _, _, err := filter.down(ssh.Marshal(globalRequest{Type: requestType, WantReply: true})); err != nil {
						t.Fatal(err)
					}
				}
				if _, _, err := filter.up([]byte{replyType}); !errors.Is(err, want) {
					t.Fatalf("err = %v, want %v", err, want)
				}
				if writes != failAt {
					t.Fatalf("writes = %v, want %v", writes, failAt)
				}
				assertTypePolicyFilterClosed(t, filter)
			})
		}
	}
}

func assertTypePolicyFilterClosed(t *testing.T, filter *typePolicyFilter) {
	t.Helper()
	if !filter.closed || filter.count != 0 || filter.head != 0 || filter.pending != [maxPendingGlobalReplies]bool{} {
		t.Fatal("filter is not closed with cleared reply state")
	}
	for _, requestType := range []string{"keepalive@openssh.com", "tcpip-forward"} {
		method, reply, err := filter.down(ssh.Marshal(globalRequest{Type: requestType, WantReply: true}))
		if !errors.Is(err, net.ErrClosed) || method != ssh.PipePacketHookTransform || reply != nil {
			t.Fatalf("closed down = %v, %v, %v, want Transform, nil, ErrClosed", method, reply, err)
		}
	}
	if _, _, err := filter.up([]byte{msgRequestSuccess}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed up error = %v, want ErrClosed", err)
	}
}

func TestTypePolicyFilterCloseClearsPendingReplies(t *testing.T) {
	filter := newTypePolicyFilter(discardDownstream, nil, disableRemoteForwardPolicy(t))
	for _, requestType := range []string{"keepalive@openssh.com", "tcpip-forward"} {
		if _, _, err := filter.down(ssh.Marshal(globalRequest{Type: requestType, WantReply: true})); err != nil {
			t.Fatal(err)
		}
	}
	filter.close()
	filter.close()
	assertTypePolicyFilterClosed(t, filter)
}

func TestTypePolicyFilterPendingReplyLimit(t *testing.T) {
	for _, overflowType := range []string{"keepalive@openssh.com", "tcpip-forward"} {
		t.Run(overflowType, func(t *testing.T) {
			filter := newTypePolicyFilter(discardDownstream, nil, disableRemoteForwardPolicy(t))
			for range maxPendingGlobalReplies {
				if _, _, err := filter.down(ssh.Marshal(globalRequest{Type: "keepalive@openssh.com", WantReply: true})); err != nil {
					t.Fatal(err)
				}
			}
			for _, requestType := range []string{"keepalive@openssh.com", "tcpip-forward"} {
				if _, _, err := filter.down(ssh.Marshal(globalRequest{Type: requestType})); err != nil {
					t.Fatalf("no-reply request consumed a slot: %v", err)
				}
			}
			method, reply, err := filter.down(ssh.Marshal(globalRequest{Type: overflowType, WantReply: true}))
			want := fmt.Sprintf("too many pending global request replies (limit %d)", maxPendingGlobalReplies)
			if err == nil || err.Error() != want || method != ssh.PipePacketHookTransform || reply != nil {
				t.Fatalf("overflow = %v, %v, %v, want Transform, nil, %q", method, reply, err, want)
			}
			assertTypePolicyFilterClosed(t, filter)
		})
	}
}

func TestTypePolicyFilterReusesReplySlots(t *testing.T) {
	writes := 0
	filter := newTypePolicyFilter(func([]byte) error {
		writes++
		return nil
	}, nil, disableRemoteForwardPolicy(t))
	for range maxPendingGlobalReplies + 1 {
		for _, requestType := range []string{"keepalive@openssh.com", "tcpip-forward", "tcpip-forward"} {
			if _, _, err := filter.down(ssh.Marshal(globalRequest{Type: requestType, WantReply: true})); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := filter.up([]byte{msgRequestSuccess}); err != nil {
			t.Fatal(err)
		}
	}
	if filter.count != 0 || writes != 3*(maxPendingGlobalReplies+1) {
		t.Fatalf("pending, writes = %v, %v", filter.count, writes)
	}
}

func TestTypePolicyFilterChannelOnlyDoesNotTrackGlobalReplies(t *testing.T) {
	filter := newTypePolicyFilter(discardDownstream, disableLocalForwardPolicy(t), nil)
	packet := ssh.Marshal(globalRequest{Type: "keepalive@openssh.com", WantReply: true})
	for range maxPendingGlobalReplies + 1 {
		method, out, err := filter.down(packet)
		if err != nil || method != ssh.PipePacketHookTransform || !bytes.Equal(out, packet) {
			t.Fatalf("down = %v, %v, %v, want unchanged request", method, out, err)
		}
	}
	if filter.count != 0 {
		t.Fatalf("pending = %d without a global request policy", filter.count)
	}
}

func mustTypePolicy(t *testing.T, kind string, allowed, denied, alwaysDenied []string) *typePolicy {
	t.Helper()

	p, err := newTypePolicy(kind, allowed, denied, alwaysDenied)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNewTypePolicy(t *testing.T) {
	t.Run("both lists set is rejected", func(t *testing.T) {
		for _, kind := range []string{"channel-types", "global-requests"} {
			for _, allowed := range [][]string{{"session"}, {""}, {" ", "\t"}} {
				for _, denied := range [][]string{{"x11"}, {""}, {" ", "\t"}} {
					p, err := newTypePolicy(kind, allowed, denied, nil)
					want := fmt.Sprintf("--allowed-%v and --denied-%v are mutually exclusive, set only one", kind, kind)
					if err == nil || err.Error() != want {
						t.Fatalf("%s: allowed=%q, denied=%q: err = %v, want %q", kind, allowed, denied, err, want)
					}
					if p != nil {
						t.Fatalf("policy = %v, want nil on error", p)
					}
				}
			}
		}
	})

	t.Run("empty lists yield no policy", func(t *testing.T) {
		for _, tt := range [][2][]string{
			{nil, nil},
			{{" ", ""}, nil},
			{nil, {""}},
		} {
			p, err := newTypePolicy("channel-types", tt[0], tt[1], nil)
			if err != nil {
				t.Fatal(err)
			}
			if p != nil {
				t.Fatalf("policy = %v, want nil", p)
			}
			// A nil *typePolicy is the documented "no policy configured"
			// value that daemon.go stores and calls into directly, so the
			// nil-receiver behavior is deliberately asserted here.
			if !p.empty() {
				t.Fatal("empty() = false, want true")
			}
			if p.blocked("session") {
				t.Fatal("blocked() = true, want false for a nil policy")
			}
		}
	})

	t.Run("whitespace is trimmed", func(t *testing.T) {
		p := mustTypePolicy(t, "channel-types", []string{" session ", ""}, nil, nil)
		if p.blocked("session") {
			t.Fatal("session should be allowed")
		}
		if !p.blocked("direct-tcpip") {
			t.Fatal("direct-tcpip should be blocked")
		}
	})

	t.Run("always denied types are merged into the deny list", func(t *testing.T) {
		p := mustTypePolicy(t, "channel-types", nil, []string{"x11"}, localForwardChannelTypes)
		for _, blocked := range append([]string{"x11"}, localForwardChannelTypes...) {
			if !p.blocked(blocked) {
				t.Fatalf("%v should be blocked", blocked)
			}
		}
		if p.blocked("session") {
			t.Fatal("session should be allowed")
		}
	})

	t.Run("always denied types are removed from the allow list", func(t *testing.T) {
		p := mustTypePolicy(t, "channel-types", []string{"session", "direct-tcpip"}, nil, localForwardChannelTypes)
		if p.blocked("session") {
			t.Fatal("session should be allowed")
		}
		if !p.blocked("direct-tcpip") {
			t.Fatal("direct-tcpip should be blocked")
		}
	})

	t.Run("an allow list emptied by always denied types blocks everything", func(t *testing.T) {
		p := mustTypePolicy(t, "channel-types", []string{"direct-tcpip"}, nil, localForwardChannelTypes)
		if p.empty() {
			t.Fatal("empty() = true, want false")
		}
		for _, blocked := range []string{"session", "direct-tcpip"} {
			if !p.blocked(blocked) {
				t.Fatalf("%v should be blocked", blocked)
			}
		}
	})
}

func TestTypePolicyBlocked(t *testing.T) {
	for _, tt := range []struct {
		name    string
		allowed []string
		denied  []string
		blocked map[string]bool
	}{
		{
			name:    "allow list denies everything else",
			allowed: []string{"session"},
			blocked: map[string]bool{
				"session":                        false,
				"direct-tcpip":                   true,
				"x11":                            true,
				"direct-streamlocal@openssh.com": true,
			},
		},
		{
			name:   "deny list allows everything else",
			denied: []string{"direct-tcpip", "x11"},
			blocked: map[string]bool{
				"session":      false,
				"direct-tcpip": true,
				"x11":          true,
			},
		},
		{
			name:    "matching is case sensitive",
			allowed: []string{"session"},
			blocked: map[string]bool{
				"session": false,
				"SESSION": true,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := mustTypePolicy(t, "channel-types", tt.allowed, tt.denied, nil)
			if p.empty() {
				t.Fatal("empty() = true, want false")
			}
			for name, want := range tt.blocked {
				if got := p.blocked(name); got != want {
					t.Fatalf("blocked(%q) = %v, want %v", name, got, want)
				}
			}
		})
	}
}

func TestTypePolicyFilterChannelPolicy(t *testing.T) {
	for _, tt := range []struct {
		name        string
		policy      *typePolicy
		channelType string
		wantBlocked bool
	}{
		{
			name:        "allow list rejects unlisted channel",
			policy:      mustTypePolicy(t, "channel-types", []string{"session"}, nil, nil),
			channelType: "direct-tcpip",
			wantBlocked: true,
		},
		{
			name:        "allow list passes listed channel",
			policy:      mustTypePolicy(t, "channel-types", []string{"session"}, nil, nil),
			channelType: "session",
		},
		{
			name:        "deny list rejects listed channel",
			policy:      mustTypePolicy(t, "channel-types", nil, []string{"x11"}, nil),
			channelType: "x11",
			wantBlocked: true,
		},
		{
			name:        "deny list passes unlisted channel",
			policy:      mustTypePolicy(t, "channel-types", nil, []string{"x11"}, nil),
			channelType: "session",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			filter := newTypePolicyFilter(discardDownstream, tt.policy, nil)
			packet := ssh.Marshal(channelOpen{Type: tt.channelType, SenderChannel: 7})

			method, out, err := filter.down(packet)
			if err != nil {
				t.Fatal(err)
			}

			if !tt.wantBlocked {
				if method != ssh.PipePacketHookTransform {
					t.Fatalf("method = %v, want PipePacketHookTransform", method)
				}
				if !bytes.Equal(out, packet) {
					t.Fatalf("packet = %v, want unchanged %v", out, packet)
				}
				return
			}

			if method != ssh.PipePacketHookReply {
				t.Fatalf("method = %v, want PipePacketHookReply", method)
			}

			var failure channelOpenFailure
			if err := ssh.Unmarshal(out, &failure); err != nil {
				t.Fatal(err)
			}
			if out[0] != msgChannelOpenFailed {
				t.Fatalf("message type = %d, want %d", out[0], msgChannelOpenFailed)
			}
			if failure.RecipientChannel != 7 {
				t.Fatalf("recipient channel = %d, want 7", failure.RecipientChannel)
			}
			if failure.ReasonCode != connectionFailedAdministratively {
				t.Fatalf("reason code = %d, want %d", failure.ReasonCode, connectionFailedAdministratively)
			}
		})
	}
}

func TestTypePolicyFilterGlobalRequestPolicy(t *testing.T) {
	for _, tt := range []struct {
		name        string
		policy      *typePolicy
		requestType string
		wantBlocked bool
	}{
		{
			name:        "allow list rejects unlisted request",
			policy:      mustTypePolicy(t, "global-requests", []string{"keepalive@openssh.com"}, nil, nil),
			requestType: "tcpip-forward",
			wantBlocked: true,
		},
		{
			name:        "allow list passes listed request",
			policy:      mustTypePolicy(t, "global-requests", []string{"keepalive@openssh.com"}, nil, nil),
			requestType: "keepalive@openssh.com",
		},
		{
			name:        "deny list rejects listed request",
			policy:      mustTypePolicy(t, "global-requests", nil, []string{"tcpip-forward"}, nil),
			requestType: "tcpip-forward",
			wantBlocked: true,
		},
		{
			name:        "deny list passes unlisted request",
			policy:      mustTypePolicy(t, "global-requests", nil, []string{"tcpip-forward"}, nil),
			requestType: "keepalive@openssh.com",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			filter := newTypePolicyFilter(discardDownstream, nil, tt.policy)
			packet := ssh.Marshal(globalRequest{Type: tt.requestType, WantReply: true})

			method, out, err := filter.down(packet)
			if err != nil {
				t.Fatal(err)
			}

			if !tt.wantBlocked {
				if method != ssh.PipePacketHookTransform {
					t.Fatalf("method = %v, want PipePacketHookTransform", method)
				}
				if !bytes.Equal(out, packet) {
					t.Fatalf("packet = %v, want unchanged %v", out, packet)
				}
				return
			}

			if method != ssh.PipePacketHookReply {
				t.Fatalf("method = %v, want PipePacketHookReply", method)
			}
			if !bytes.Equal(out, []byte{msgRequestFailure}) {
				t.Fatalf("reply = %v, want SSH_MSG_REQUEST_FAILURE", out)
			}
		})
	}
}

// TestTypePolicyFilterGlobalRequestPolicyDropsWithoutReply verifies that a
// blocked global request that did not ask for a reply is dropped silently
// rather than answered, mirroring the disable-remote-forwarding behavior.
func TestTypePolicyFilterGlobalRequestPolicyDropsWithoutReply(t *testing.T) {
	filter := newTypePolicyFilter(discardDownstream, nil, mustTypePolicy(t, "global-requests", []string{"keepalive@openssh.com"}, nil, nil))
	packet := ssh.Marshal(globalRequest{Type: "tcpip-forward", WantReply: false})

	method, out, err := filter.down(packet)
	if err != nil {
		t.Fatal(err)
	}
	if method != ssh.PipePacketHookTransform {
		t.Fatalf("method = %v, want PipePacketHookTransform", method)
	}
	if out != nil {
		t.Fatalf("packet = %v, want nil", out)
	}
}
