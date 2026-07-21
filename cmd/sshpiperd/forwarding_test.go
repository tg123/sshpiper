package main

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestForwardingFilterDisablesRemoteForwarding(t *testing.T) {
	filter := forwardingFilter{disableRemote: true}

	for _, requestType := range []string{"tcpip-forward", "cancel-tcpip-forward"} {
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
	filter := forwardingFilter{disableRemote: true}
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
	filter := forwardingFilter{disableLocal: true}
	packet := ssh.Marshal(channelOpen{Type: "direct-tcpip", SenderChannel: 42})

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
}

func TestForwardingFilterAllowsUnblockedRequests(t *testing.T) {
	tests := []struct {
		name   string
		filter forwardingFilter
		packet []byte
	}{
		{
			name:   "remote forwarding enabled",
			filter: forwardingFilter{},
			packet: ssh.Marshal(globalRequest{Type: "tcpip-forward", WantReply: true}),
		},
		{
			name:   "unrelated global request",
			filter: forwardingFilter{disableRemote: true},
			packet: ssh.Marshal(globalRequest{Type: "keepalive@openssh.com", WantReply: true}),
		},
		{
			name:   "local forwarding enabled",
			filter: forwardingFilter{},
			packet: ssh.Marshal(channelOpen{Type: "direct-tcpip", SenderChannel: 42}),
		},
		{
			name:   "session channel",
			filter: forwardingFilter{disableLocal: true},
			packet: ssh.Marshal(channelOpen{Type: "session", SenderChannel: 42}),
		},
		{
			name:   "unrelated packet",
			filter: forwardingFilter{disableLocal: true, disableRemote: true},
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
	filter := forwardingFilter{disableLocal: true, disableRemote: true}

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
