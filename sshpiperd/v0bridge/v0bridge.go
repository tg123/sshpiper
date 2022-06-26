package v0bridge

import (
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"
)

type AuthPipeType int

const (
	// AuthPipeTypePassThrough does nothing but pass auth message to upstream
	AuthPipeTypePassThrough AuthPipeType = iota

	// AuthPipeTypeMap converts auth message to AuthMetod return by callback and pass it to upstream
	AuthPipeTypeMap

	// AuthPipeTypeDiscard discards auth message, do not pass it to uptream
	AuthPipeTypeDiscard

	// AuthPipeTypeNone converts auth message to NoneAuth and pass it to upstream
	AuthPipeTypeNone
)

// AuthPipe contains the callbacks of auth msg mapping from downstream to upstream
//
// when AuthPipeType == AuthPipeTypeMap && AuthMethod == PublicKey
// SSHPiper will sign the auth packet message using the returned Signer.
// This func might be called twice, one is for query message, the other
// is real auth packet message.
// If any error occurs during this period, a NoneAuth packet will be sent to
// upstream ssh server instead.
// More info: https://github.com/tg123/sshpiper#publickey-sign-again
type AuthPipe struct {
	// Username to upstream
	User string

	// NoneAuthCallback, if non-nil, is called when downstream requests a none auth,
	// typically the first auth msg from client to see what auth methods can be used..
	NoneAuthCallback func(conn ssh.ConnMetadata) (AuthPipeType, ssh.AuthMethod, error)

	// PublicKeyCallback, if non-nil, is called when downstream requests a password auth.
	PasswordCallback func(conn ssh.ConnMetadata, password []byte) (AuthPipeType, ssh.AuthMethod, error)

	// PublicKeyCallback, if non-nil, is called when downstream requests a publickey auth.
	PublicKeyCallback func(conn ssh.ConnMetadata, key ssh.PublicKey) (AuthPipeType, ssh.AuthMethod, error)

	// UpstreamHostKeyCallback is called during the cryptographic
	// handshake to validate the uptream server's host key. The piper
	// configuration must supply this callback for the connection
	// to succeed. The functions InsecureIgnoreHostKey or
	// FixedHostKey can be used for simplistic host key checks.
	UpstreamHostKeyCallback ssh.HostKeyCallback
}

type proxy struct {
	handler       func(conn ssh.ConnMetadata, challengeContext ssh.ChallengeContext) (net.Conn, *AuthPipe, error)
	allowedMethod map[string]bool
}

// ChallengedUsername unused
func (p *proxy) ChallengedUsername() string {
	return ""
}

// Meta unused
func (p *proxy) Meta() interface{} {
	return nil
}

func (p *proxy) CreateChallengeContext(conn ssh.ConnMetadata) (ssh.ChallengeContext, error) {
	return p, nil
}

func (p *proxy) createUpstream(conn net.Conn, pipe *AuthPipe, authType AuthPipeType, oldMethod, mappedMethod ssh.AuthMethod) (*ssh.Upstream, error) {

	clientConfig := ssh.ClientConfig{
		User:            pipe.User,
		HostKeyCallback: pipe.UpstreamHostKeyCallback,
	}

	switch authType {
	case AuthPipeTypePassThrough:
		clientConfig.Auth = []ssh.AuthMethod{oldMethod}

	case AuthPipeTypeMap:
		clientConfig.Auth = []ssh.AuthMethod{mappedMethod}
	case AuthPipeTypeDiscard:
		return nil, fmt.Errorf("msg is discarded")
	case AuthPipeTypeNone:
		clientConfig.Auth = []ssh.AuthMethod{ssh.NoneAuth()}
	}

	return &ssh.Upstream{
		Conn:         conn,
		ClientConfig: clientConfig,
	}, nil
}

func (p *proxy) NextAuthMethods(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) ([]string, error) {
	var allow []string

	for k, v := range p.allowedMethod {
		if v {
			allow = append(allow, k)
		}
	}

	return allow, nil
}

func (p *proxy) UpstreamAuthFailureCallback(onn ssh.ConnMetadata, method string, err error, challengeCtx ssh.ChallengeContext) {
	noMoreMethodErr, ok := err.(ssh.NoMoreMethodsErr)
	if ok {
		for _, allowed := range noMoreMethodErr.Allowed {
			p.allowedMethod[allowed] = true
		}

		return
	}

	p.allowedMethod[method] = false
}

func (p *proxy) NoneAuthCallback(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
	c, pipe, err := p.handler(conn, challengeCtx)
	if err != nil {
		return nil, err
	}

	if pipe.NoneAuthCallback == nil {
		return p.createUpstream(c, pipe, AuthPipeTypePassThrough, ssh.NoneAuth(), nil)
	}

	t, m, err := pipe.NoneAuthCallback(conn)
	if err != nil {
		return nil, err
	}

	return p.createUpstream(c, pipe, t, ssh.NoneAuth(), m)
}

func (p *proxy) PasswordCallback(conn ssh.ConnMetadata, password []byte, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
	c, pipe, err := p.handler(conn, challengeCtx)
	if err != nil {
		return nil, err
	}

	if pipe.PasswordCallback == nil {
		return p.createUpstream(c, pipe, AuthPipeTypePassThrough, ssh.Password(string(password)), nil)
	}

	t, m, err := pipe.PasswordCallback(conn, password)
	if err != nil {
		return nil, err
	}

	return p.createUpstream(c, pipe, t, ssh.Password(string(password)), m)
}

func (p *proxy) PublicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
	c, pipe, err := p.handler(conn, challengeCtx)
	if err != nil {
		return nil, err
	}

	if pipe.PublicKeyCallback == nil {
		return p.createUpstream(c, pipe, AuthPipeTypePassThrough, ssh.NoneAuth(), nil)
	}

	t, m, err := pipe.PublicKeyCallback(conn, key)
	if err != nil {
		return nil, err
	}

	return p.createUpstream(c, pipe, t, ssh.NoneAuth(), m) // cannt passthrough public key, use none instead
}

func InstallUpstream(config *ssh.PiperConfig, handler func(conn ssh.ConnMetadata, challengeContext ssh.ChallengeContext) (net.Conn, *AuthPipe, error)) {

	p := &proxy{
		handler: handler,
		allowedMethod: map[string]bool{
			"none": true,
		},
	}

	config.CreateChallengeContext = p.CreateChallengeContext
	config.NextAuthMethods = p.NextAuthMethods
	config.UpstreamAuthFailureCallback = p.UpstreamAuthFailureCallback
	config.NoneAuthCallback = p.NoneAuthCallback
	config.PasswordCallback = p.PasswordCallback
	config.PublicKeyCallback = p.PublicKeyCallback
}
