package main

import "golang.org/x/crypto/ssh"

const (
	msgGlobalRequest     = 80
	msgRequestFailure    = 82
	msgChannelOpen       = 90
	msgChannelOpenFailed = 92

	connectionFailedAdministratively = 1
)

type forwardingFilter struct {
	disableLocal  bool
	disableRemote bool
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

func (f forwardingFilter) down(packet []byte) (ssh.PipePacketHookMethod, []byte, error) {
	if len(packet) == 0 {
		return ssh.PipePacketHookTransform, packet, nil
	}

	switch packet[0] {
	case msgGlobalRequest:
		var request globalRequest
		if err := ssh.Unmarshal(packet, &request); err != nil {
			return ssh.PipePacketHookTransform, packet, nil
		}
		if !f.disableRemote || (request.Type != "tcpip-forward" && request.Type != "cancel-tcpip-forward") {
			return ssh.PipePacketHookTransform, packet, nil
		}
		if !request.WantReply {
			return ssh.PipePacketHookTransform, nil, nil
		}
		return ssh.PipePacketHookReply, ssh.Marshal(globalRequestFailure{}), nil

	case msgChannelOpen:
		var open channelOpen
		if err := ssh.Unmarshal(packet, &open); err != nil {
			return ssh.PipePacketHookTransform, packet, nil
		}
		if !f.disableLocal || open.Type != "direct-tcpip" {
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
