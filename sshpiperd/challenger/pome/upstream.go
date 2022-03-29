package pome

import (
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/tg123/sshpiper/sshpiperd/upstream"
	"github.com/tg123/sshpiper/sshpiperd/utils"
)

func (p *pome) authWithPipe(conn ssh.ConnMetadata, challengeContext ssh.AdditionalChallengeContext) (net.Conn, *ssh.AuthPipe, error) {

	pipe, ok := challengeContext.Meta().(pipe)

	if !ok {
		return nil, nil, fmt.Errorf("bad pome context")
	}

	host, port, err := upstream.SplitHostPortForSSH(pipe.Address)
	if err != nil {
		return nil, nil, pipe.say("Not add Please check your configure")
	}

	addr := fmt.Sprintf("%v:%v", utils.FormatIPAddress(host), port)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, nil, pipe.say(fmt.Sprintf("Cannot connect to %v, reason: %v", addr, err))
	}

	callback := func() (ssh.AuthPipeType, ssh.AuthMethod, error) {

		switch pipe.Auth {
		case "key":

			private, err := ssh.ParsePrivateKey([]byte(pipe.PrivateKey))
			if err != nil {
				return ssh.AuthPipeTypeNone, nil, err
			}

			return ssh.AuthPipeTypeMap, ssh.PublicKeys(private), nil
		case "pass":
			return ssh.AuthPipeTypeMap, ssh.Password(pipe.UpPassword), nil
		}

		return ssh.AuthPipeTypeNone, nil, fmt.Errorf("unsupport auth type %v", pipe.Auth)
	}

	return c, &ssh.AuthPipe{
		User: pipe.Username,

		NoneAuthCallback: func(conn ssh.ConnMetadata) (ssh.AuthPipeType, ssh.AuthMethod, error) {
			return callback()
		},

		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (ssh.AuthPipeType, ssh.AuthMethod, error) {
			return callback()
		},

		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {
			return callback()
		},

		UpstreamHostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, nil
}
