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
		if !f.disableRemote || !isRemoteForwardRequestType(request.Type) {
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
