package main

import (
	"bytes"
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

func TestForwardingFilterDisablesRemoteForwarding(t *testing.T) {
	filter := newForwardingFilter(nil, disableRemoteForwardPolicy(t))

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

func TestForwardingFilterDropsRemoteForwardingWithoutReply(t *testing.T) {
	filter := newForwardingFilter(nil, disableRemoteForwardPolicy(t))
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

func TestForwardingFilterDisablesLocalForwarding(t *testing.T) {
	filter := newForwardingFilter(disableLocalForwardPolicy(t), nil)

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

func TestForwardingFilterAllowsUnblockedRequests(t *testing.T) {
	tests := []struct {
		name   string
		filter *forwardingFilter
		packet []byte
	}{
		{
			name:   "remote forwarding enabled",
			filter: newForwardingFilter(nil, nil),
			packet: ssh.Marshal(globalRequest{Type: "tcpip-forward", WantReply: true}),
		},
		{
			name:   "unrelated global request",
			filter: newForwardingFilter(nil, disableRemoteForwardPolicy(t)),
			packet: ssh.Marshal(globalRequest{Type: "keepalive@openssh.com", WantReply: true}),
		},
		{
			name:   "local forwarding enabled",
			filter: newForwardingFilter(nil, nil),
			packet: ssh.Marshal(channelOpen{Type: "direct-tcpip", SenderChannel: 42}),
		},
		{
			name:   "session channel",
			filter: newForwardingFilter(disableLocalForwardPolicy(t), nil),
			packet: ssh.Marshal(channelOpen{Type: "session", SenderChannel: 42}),
		},
		{
			name:   "unrelated packet",
			filter: newForwardingFilter(disableLocalForwardPolicy(t), disableRemoteForwardPolicy(t)),
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

func TestForwardingFilterAllowsMalformedRequests(t *testing.T) {
	filter := newForwardingFilter(disableLocalForwardPolicy(t), disableRemoteForwardPolicy(t))

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

// TestForwardingFilterPreservesGlobalRequestReplyOrder verifies that a
// locally-generated failure for a blocked remote-forward request does not
// jump ahead of the genuine upstream reply to an earlier, unrelated,
// want-reply global request. SSH_MSG_REQUEST_SUCCESS/FAILURE carry no
// request ID, so the client matches replies to requests strictly by the
// order they arrive; delivering them out of order would corrupt that
// matching.
func TestForwardingFilterPreservesGlobalRequestReplyOrder(t *testing.T) {
	filter := newForwardingFilter(nil, disableRemoteForwardPolicy(t))

	// First request: unrelated, forwarded upstream, no reply yet.
	unrelated := ssh.Marshal(globalRequest{Type: "keepalive@openssh.com", WantReply: true})
	method, out, err := filter.down(unrelated)
	if err != nil {
		t.Fatal(err)
	}
	if method != ssh.PipePacketHookTransform {
		t.Fatalf("method = %v, want PipePacketHookTransform", method)
	}
	if !bytes.Equal(out, unrelated) {
		t.Fatalf("packet = %v, want unchanged %v", out, unrelated)
	}

	// Second request: blocked remote-forward request, sent right after.
	// down() must not answer it until the first request's upstream reply
	// has been observed via up().
	blocked := ssh.Marshal(globalRequest{Type: "tcpip-forward", WantReply: true})
	done := make(chan struct{})
	var (
		blockedMethod ssh.PipePacketHookMethod
		blockedReply  []byte
		blockedErr    error
	)
	go func() {
		blockedMethod, blockedReply, blockedErr = filter.down(blocked)
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("down answered the blocked request before the earlier request's upstream reply arrived")
	case <-time.After(100 * time.Millisecond):
	}

	// Deliver the upstream's genuine reply to the first (unrelated) request.
	if _, _, err := filter.up([]byte{msgRequestSuccess}); err != nil {
		t.Fatal(err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for down to answer the blocked request after the earlier reply arrived")
	}

	if blockedErr != nil {
		t.Fatal(blockedErr)
	}
	if blockedMethod != ssh.PipePacketHookReply {
		t.Fatalf("method = %v, want PipePacketHookReply", blockedMethod)
	}
	if !bytes.Equal(blockedReply, []byte{msgRequestFailure}) {
		t.Fatalf("reply = %v, want SSH_MSG_REQUEST_FAILURE", blockedReply)
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
		if _, err := newTypePolicy("channel-types", []string{"session"}, []string{"x11"}, nil); err == nil {
			t.Fatal("expected an error when both the allow and deny list are set")
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

func TestForwardingFilterChannelPolicy(t *testing.T) {
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
			filter := newForwardingFilter(tt.policy, nil)
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

func TestForwardingFilterGlobalRequestPolicy(t *testing.T) {
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
			filter := newForwardingFilter(nil, tt.policy)
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

// TestForwardingFilterGlobalRequestPolicyDropsWithoutReply verifies that a
// blocked global request that did not ask for a reply is dropped silently
// rather than answered, mirroring the disable-remote-forwarding behavior.
func TestForwardingFilterGlobalRequestPolicyDropsWithoutReply(t *testing.T) {
	filter := newForwardingFilter(nil, mustTypePolicy(t, "global-requests", []string{"keepalive@openssh.com"}, nil, nil))
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
