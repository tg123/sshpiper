package main

import (
	"bytes"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestForwardingFilterDisablesRemoteForwarding(t *testing.T) {
	filter := newForwardingFilter(false, true)

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
	filter := newForwardingFilter(false, true)
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
	filter := newForwardingFilter(true, false)

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
			filter: newForwardingFilter(false, false),
			packet: ssh.Marshal(globalRequest{Type: "tcpip-forward", WantReply: true}),
		},
		{
			name:   "unrelated global request",
			filter: newForwardingFilter(false, true),
			packet: ssh.Marshal(globalRequest{Type: "keepalive@openssh.com", WantReply: true}),
		},
		{
			name:   "local forwarding enabled",
			filter: newForwardingFilter(false, false),
			packet: ssh.Marshal(channelOpen{Type: "direct-tcpip", SenderChannel: 42}),
		},
		{
			name:   "session channel",
			filter: newForwardingFilter(true, false),
			packet: ssh.Marshal(channelOpen{Type: "session", SenderChannel: 42}),
		},
		{
			name:   "unrelated packet",
			filter: newForwardingFilter(true, true),
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
	filter := newForwardingFilter(true, true)

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
	filter := newForwardingFilter(false, true)

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
