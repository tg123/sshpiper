package grpcupstream

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/tg123/remotesigner"
	"github.com/tg123/remotesigner/grpcsigner"
	"github.com/tg123/sshpiper/sshpiperd/upstream"
	"golang.org/x/crypto/ssh"
)

func (p *plugin) timeoutCtx() (context.Context, context.CancelFunc) {
	d := time.Now().Add(time.Duration(p.Config.Timeout) * time.Second)
	return context.WithDeadline(context.Background(), d)
}

func (p *plugin) mapauth(conn ssh.ConnMetadata, metadata string, typ MapAuthRequest_Authtype, param []byte) (ssh.AuthPipeType, ssh.AuthMethod, error) {
	ctx, cancel := p.timeoutCtx()
	defer cancel()

	a, err := p.upstreamClient.MapAuth(ctx, &MapAuthRequest{
		UserName:  conn.User(),
		FromAddr:  conn.RemoteAddr().String(),
		AuthType:  typ,
		AuthParam: param,
		Metadata:  metadata,
	})

	if err != nil {
		return ssh.AuthPipeTypeDiscard, nil, err
	}

	switch a.MappedAuthType {
	case MapAuthReply_PASSTHROUGH:
		return ssh.AuthPipeTypePassThrough, nil, nil
	case MapAuthReply_DISCARD:
		return ssh.AuthPipeTypeDiscard, nil, nil
	case MapAuthReply_NONE:
		return ssh.AuthPipeTypeNone, nil, nil

	case MapAuthReply_PASSWORD:
		return ssh.AuthPipeTypeMap, ssh.Password(string(a.MappedAuthParam)), nil
	case MapAuthReply_PRIVATEKEY:

		private, err := ssh.ParsePrivateKey(a.MappedAuthParam)
		if err != nil {
			return ssh.AuthPipeTypeDiscard, nil, err
		}

		return ssh.AuthPipeTypeMap, ssh.PublicKeys(private), nil
	case MapAuthReply_REMOTESIGNER:
		rs := remotesigner.New(grpcsigner.New(p.remotesignerClient, string(a.MappedAuthParam)))
		signer, err := ssh.NewSignerFromSigner(rs)
		if err != nil {
			return ssh.AuthPipeTypeDiscard, nil, err
		}

		return ssh.AuthPipeTypeMap, ssh.PublicKeys(signer), nil
	default:
		return ssh.AuthPipeTypeDiscard, nil, nil
	}
}

func (p *plugin) verifyHostKey(hostname string, remote net.Addr, key ssh.PublicKey) error {

	ctx, cancel := p.timeoutCtx()
	defer cancel()

	v, err := p.upstreamClient.VerifyHostKey(ctx, &VerifyHostKeyRequest{
		Hostname: hostname,
		Address:  remote.String(),
		Key:      key.Marshal(),
	})

	if err != nil {
		return err
	}

	if !v.Verified {
		return fmt.Errorf("host key mismatch")
	}

	return nil
}

func (p *plugin) findUpstream(conn ssh.ConnMetadata, challengeContext ssh.AdditionalChallengeContext) (net.Conn, *ssh.AuthPipe, error) {
	ctx, cancel := p.timeoutCtx()
	defer cancel()

	u, err := p.upstreamClient.FindUpstream(ctx, &FindUpstreamRequest{
		UserName: conn.User(),
		FromAddr: conn.RemoteAddr().String(),
	})
	if err != nil {
		return nil, nil, err
	}

	c, err := upstream.DialForSSH(u.ToAddr)
	if err != nil {
		return nil, nil, err
	}

	a := &ssh.AuthPipe{
		User:                    u.MappedUserName,
		UpstreamHostKeyCallback: p.verifyHostKey,
	}

	a.NoneAuthCallback = func(conn ssh.ConnMetadata) (ssh.AuthPipeType, ssh.AuthMethod, error) {
		return p.mapauth(conn, u.Metadata, MapAuthRequest_NONE, nil)
	}

	a.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (ssh.AuthPipeType, ssh.AuthMethod, error) {
		return p.mapauth(conn, u.Metadata, MapAuthRequest_PASSWORD, password)
	}

	a.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {
		return p.mapauth(conn, u.Metadata, MapAuthRequest_PUBLICKEY, key.Marshal())
	}

	return c, a, nil
}
