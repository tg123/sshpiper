// Copyright 2014, 2015 tgic<farmer1992@gmail.com>. All rights reserved.
// this file is governed by MIT-license
//
// https://github.com/tg123/sshpiper

package ssh

import (
	"errors"
	"fmt"
	"net"
)

// AuthPipeType declares how sshpiper handle piped auth message
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

	// PublicKeyCallback, if non-nil, is called when downstream requests a password auth.
	PasswordCallback func(conn ConnMetadata, password []byte) (AuthPipeType, AuthMethod, error)

	// PublicKeyCallback, if non-nil, is called when downstream requests a publickey auth.
	PublicKeyCallback func(conn ConnMetadata, key PublicKey) (AuthPipeType, AuthMethod, error)

	// UpstreamHostKeyCallback is called during the cryptographic
	// handshake to validate the uptream server's host key. The piper
	// configuration must supply this callback for the connection
	// to succeed. The functions InsecureIgnoreHostKey or
	// FixedHostKey can be used for simplistic host key checks.
	UpstreamHostKeyCallback HostKeyCallback
}

// The context returned by AdditionalChallenge and will pass to FindUpstream for building
// upstream AuthPipe
type AdditionalChallengeContext interface {

	// Chanllenger name
	ChallengerName() string

	// Meta info filled by chanllenger
	// can be nil if no meta data
	Meta() interface{}

	// Username used during the chanllenge
	// Can be different from ConnMeta.User() and could be a useful hint in FindUpstream
	ChallengedUsername() string
}

// PiperConfig holds SSHPiper specific configuration data.
type PiperConfig struct {
	Config

	hostKeys []Signer

	// AdditionalChallenge, if non-nil, is called before calling FindUpstream.
	// This allows you do a KeyboardInteractiveChallenge before connecting to upstream.
	// It must return non error if downstream passed the challenge, otherwise,
	// the piped connection will be closed.
	//
	// AdditionalChallengeContext can be nil if challenger has no more information to provide.
	AdditionalChallenge func(conn ConnMetadata, client KeyboardInteractiveChallenge) (AdditionalChallengeContext, error)

	// FindUpstream, must not be nil, is called when SSHPiper decided to establish a
	// ssh connection to upstream server.  a connection, net.Conn, to upstream
	// and upstream username should be returned.
	// SSHPiper will use the username from downstream if empty username is returned.
	// If any error occurs, the piped connection will be closed.
	FindUpstream func(conn ConnMetadata, challengeCtx AdditionalChallengeContext) (net.Conn, *AuthPipe, error)

	// ServerVersion is the version identification string to announce in
	// the public handshake.
	// If empty, a reasonable default is used.
	// Note that RFC 4253 section 4.2 requires that this string start with
	// "SSH-2.0-".
	ServerVersion string

	// BannerCallback, if present, is called and the return string is sent to
	// the client after key exchange completed but before authentication.
	BannerCallback func(conn ConnMetadata) string
}

type upstream struct{ *connection }
type downstream struct{ *connection }

type pipedConn struct {
	upstream   *upstream
	downstream *downstream

	processAuthMsg func(msg *userAuthRequestMsg) (*userAuthRequestMsg, error)

	hookUpstreamMsg   func(msg []byte) ([]byte, error)
	hookDownstreamMsg func(msg []byte) ([]byte, error)
}

// PiperConn is a piped SSH connection, linking upstream ssh server and
// downstream ssh client together. After the piped connection was created,
// The downstream ssh client is authenticated by upstream ssh server and
// AdditionalChallenge from SSHPiper.
type PiperConn struct {
	*pipedConn

	HookUpstreamMsg   func(conn ConnMetadata, msg []byte) ([]byte, error)
	HookDownstreamMsg func(conn ConnMetadata, msg []byte) ([]byte, error)
}

// Wait blocks until the piped connection has shut down, and returns the
// error causing the shutdown.
func (p *PiperConn) Wait() error {

	p.pipedConn.hookUpstreamMsg = func(msg []byte) ([]byte, error) {
		if p.HookUpstreamMsg != nil {
			// api always using p.downstream as conn meta
			return p.HookUpstreamMsg(p.downstream, msg)
		}

		return msg, nil
	}

	p.pipedConn.hookDownstreamMsg = func(msg []byte) ([]byte, error) {
		if p.HookDownstreamMsg != nil {
			return p.HookDownstreamMsg(p.downstream, msg)
		}

		return msg, nil
	}

	return p.pipedConn.loop()
}

// Close the piped connection create by SSHPiper
func (p *PiperConn) Close() {
	p.pipedConn.Close()
}

// UpstreamConnMeta returns the ConnMetadata of the piper and upstream
func (p *PiperConn) UpstreamConnMeta() ConnMetadata {
	return p.pipedConn.upstream
}

// DownstreamConnMeta returns the ConnMetadata of the piper and downstream
func (p *PiperConn) DownstreamConnMeta() ConnMetadata {
	return p.pipedConn.downstream
}

// AddHostKey adds a private key as a SSHPiper host key. If an existing host
// key exists with the same algorithm, it is overwritten. Each SSHPiper
// config must have at least one host key.
func (s *PiperConfig) AddHostKey(key Signer) {
	for i, k := range s.hostKeys {
		if k.PublicKey().Type() == key.PublicKey().Type() {
			s.hostKeys[i] = key
			return
		}
	}

	s.hostKeys = append(s.hostKeys, key)
}

// NewSSHPiperConn starts a piped ssh connection witch conn as its downstream transport.
// It handshake with downstream ssh client and upstream ssh server provicde by FindUpstream.
// If either handshake is unsuccessful, the whole piped connection will be closed.
func NewSSHPiperConn(conn net.Conn, piper *PiperConfig) (pipe *PiperConn, err error) {

	if piper.FindUpstream == nil {
		return nil, errors.New("sshpiper: must specify FindUpstream")
	}

	d, err := newDownstream(conn, &ServerConfig{
		Config:        piper.Config,
		hostKeys:      piper.hostKeys,
		ServerVersion: piper.ServerVersion,
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if pipe == nil {
			d.Close()
		}
	}()

	userAuthReq, err := d.nextAuthMsg()
	if err != nil {
		return nil, err
	}

	d.user = userAuthReq.User

	if piper.BannerCallback != nil {
		msg := piper.BannerCallback(d)
		if msg != "" {
			bannerMsg := &userAuthBannerMsg{
				Message: msg,
			}
			if err := d.transport.writePacket(Marshal(bannerMsg)); err != nil {
				return nil, err
			}
		}
	}

	var challengeCtx AdditionalChallengeContext

	// need additional challenge
	if piper.AdditionalChallenge != nil {

		for {
			err := d.transport.writePacket(Marshal(&userAuthFailureMsg{
				Methods: []string{"keyboard-interactive"},
			}))

			if err != nil {
				return nil, err
			}

			userAuthReq, err := d.nextAuthMsg()

			if err != nil {
				return nil, err
			}

			if userAuthReq.Method == "keyboard-interactive" {
				break
			}
		}

		prompter := &sshClientKeyboardInteractive{d.connection}
		challengeCtx, err = piper.AdditionalChallenge(d, prompter.Challenge)

		if err != nil {
			return nil, err
		}
	}

	upconn, pipeauth, err := piper.FindUpstream(d, challengeCtx)
	if err != nil {
		return nil, err
	}

	if pipeauth.UpstreamHostKeyCallback == nil {
		return nil, errors.New("sshpiper: must specify UpstreamHostKeyCallback")
	}

	mappedUser := pipeauth.User
	addr := upconn.RemoteAddr().String()

	if mappedUser == "" {
		mappedUser = d.user
	}

	u, err := newUpstream(upconn, addr, &ClientConfig{
		HostKeyCallback: pipeauth.UpstreamHostKeyCallback,
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if pipe == nil {
			u.Close()
		}
	}()
	u.user = mappedUser

	p := &pipedConn{
		upstream:   u,
		downstream: d,
	}

	p.processAuthMsg = func(msg *userAuthRequestMsg) (*userAuthRequestMsg, error) {

		var authType = AuthPipeTypePassThrough
		var authMethod AuthMethod

		switch msg.Method {
		case "publickey":

			if pipeauth.PublicKeyCallback == nil {
				break
			}

			// pubKey MAP
			downKey, isQuery, sig, err := parsePublicKeyMsg(msg)
			if err != nil {
				return nil, err
			}

			authType, authMethod, err = pipeauth.PublicKeyCallback(d, downKey)
			if err != nil {
				return nil, err
			}

			if isQuery {
				// reply for query msg
				// skip query from upstream
				err = p.ack(downKey)
				if err != nil {
					return nil, err
				}

				// discard msg
				return nil, nil
			}

			ok, err := p.checkPublicKey(msg, downKey, sig)

			if err != nil {
				return nil, err
			}

			if !ok {
				return noneAuthMsg(mappedUser), nil
			}

		case "password":
			if pipeauth.PasswordCallback == nil {
				break
			}

			payload := msg.Payload
			if len(payload) < 1 || payload[0] != 0 {
				return nil, parseError(msgUserAuthRequest)
			}
			payload = payload[1:]
			password, payload, ok := parseString(payload)
			if !ok || len(payload) > 0 {
				return nil, parseError(msgUserAuthRequest)
			}

			authType, authMethod, err = pipeauth.PasswordCallback(d, password)
			if err != nil {
				return nil, err
			}

		default:
		}

		switch authType {
		case AuthPipeTypePassThrough:
			msg.User = mappedUser
			return msg, nil
		case AuthPipeTypeDiscard:
			return nil, nil
		case AuthPipeTypeNone:
			return noneAuthMsg(mappedUser), nil
		case AuthPipeTypeMap:
		}

		// map publickey, password, etc to auth

		switch authMethod.method() {
		case "publickey":

			f, ok := authMethod.(publicKeyCallback)

			if !ok {
				return nil, errors.New("sshpiper: publicKeyCallback type assertions failed")
			}

			signers, err := f()
			// no mapped user change it to none or error occur
			if err != nil || len(signers) == 0 {
				return nil, err
			}

			for _, signer := range signers {
				msg, err = p.signAgain(mappedUser, msg, signer)
				if err != nil {
					return nil, err
				}
				return msg, nil
			}
		case "password":

			f, ok := authMethod.(passwordCallback)

			if !ok {
				return nil, errors.New("sshpiper: passwordCallback type assertions failed")
			}

			pw, err := f()
			if err != nil {
				return nil, err
			}

			type passwordAuthMsg struct {
				User     string `sshtype:"50"`
				Service  string
				Method   string
				Reply    bool
				Password string
			}

			Unmarshal(Marshal(passwordAuthMsg{
				User:     mappedUser,
				Service:  serviceSSH,
				Method:   "password",
				Reply:    false,
				Password: pw,
			}), msg)

			return msg, nil

		default:

		}

		msg.User = mappedUser
		return msg, nil
	}

	err = p.pipeAuth(userAuthReq)
	if err != nil {
		return nil, err
	}

	return &PiperConn{pipedConn: p}, nil
}

func (pipe *pipedConn) ack(key PublicKey) error {
	okMsg := userAuthPubKeyOkMsg{
		Algo:   key.Type(),
		PubKey: key.Marshal(),
	}

	return pipe.downstream.transport.writePacket(Marshal(&okMsg))
}

// not used after method to method map enable
//func (pipe *pipedConn) validAndAck(user string, upKey, downKey PublicKey) (*userAuthRequestMsg, error) {
//
//	ok, err := validateKey(upKey, user, pipe.upstream.transport)
//
//	if ok {
//
//		if err = pipe.ack(downKey); err != nil {
//			return nil, err
//		}
//
//		return nil, nil
//	}
//
//	return noneAuthMsg(user), nil
//}

func (pipe *pipedConn) checkPublicKey(msg *userAuthRequestMsg, pubkey PublicKey, sig *Signature) (bool, error) {

	if !isAcceptableAlgo(sig.Format) {
		return false, fmt.Errorf("ssh: algorithm %q not accepted", sig.Format)
	}
	signedData := buildDataSignedForAuth(pipe.downstream.transport.getSessionID(), *msg, []byte(pubkey.Type()), pubkey.Marshal())

	if err := pubkey.Verify(signedData, sig); err != nil {
		return false, nil
	}

	return true, nil
}

func (pipe *pipedConn) signAgain(user string, msg *userAuthRequestMsg, signer Signer) (*userAuthRequestMsg, error) {

	rand := pipe.upstream.transport.config.Rand
	session := pipe.upstream.transport.getSessionID()

	upKey := signer.PublicKey()
	upKeyData := upKey.Marshal()

	sign, err := signer.Sign(rand, buildDataSignedForAuth(session, userAuthRequestMsg{
		User:    user,
		Service: serviceSSH,
		Method:  "publickey",
	}, []byte(upKey.Type()), upKeyData))
	if err != nil {
		return nil, err
	}

	// manually wrap the serialized signature in a string
	s := Marshal(sign)
	sig := make([]byte, stringLength(len(s)))
	marshalString(sig, s)

	pubkeyMsg := &publickeyAuthMsg{
		User:     user,
		Service:  serviceSSH,
		Method:   "publickey",
		HasSig:   true,
		Algoname: upKey.Type(),
		PubKey:   upKeyData,
		Sig:      sig,
	}

	Unmarshal(Marshal(pubkeyMsg), msg)

	return msg, nil
}

func parsePublicKeyMsg(userAuthReq *userAuthRequestMsg) (PublicKey, bool, *Signature, error) {
	if userAuthReq.Method != "publickey" {
		return nil, false, nil, fmt.Errorf("not a publickey auth msg")
	}

	payload := userAuthReq.Payload
	if len(payload) < 1 {
		return nil, false, nil, parseError(msgUserAuthRequest)
	}
	isQuery := payload[0] == 0
	payload = payload[1:]
	algoBytes, payload, ok := parseString(payload)
	if !ok {
		return nil, false, nil, parseError(msgUserAuthRequest)
	}
	algo := string(algoBytes)
	if !isAcceptableAlgo(algo) {
		return nil, false, nil, fmt.Errorf("ssh: algorithm %q not accepted", algo)
	}

	pubKeyData, payload, ok := parseString(payload)
	if !ok {
		return nil, false, nil, parseError(msgUserAuthRequest)
	}

	pubKey, err := ParsePublicKey(pubKeyData)
	if err != nil {
		return nil, false, nil, err
	}

	var sig *Signature
	if !isQuery {
		sig, payload, ok = parseSignature(payload)
		if !ok || len(payload) > 0 {
			return nil, false, nil, parseError(msgUserAuthRequest)
		}
	}

	return pubKey, isQuery, sig, nil
}

func piping(dst, src packetConn, hooker func(msg []byte) ([]byte, error)) error {
	for {
		p, err := src.readPacket()

		if err != nil {
			return err
		}

		p, err = hooker(p)

		if err != nil {
			return err
		}

		err = dst.writePacket(p)

		if err != nil {
			return err
		}
	}
}

func (pipe *pipedConn) loop() error {
	c := make(chan error)

	go func() {
		c <- piping(pipe.upstream.transport, pipe.downstream.transport, pipe.hookDownstreamMsg)
	}()

	go func() {
		c <- piping(pipe.downstream.transport, pipe.upstream.transport, pipe.hookUpstreamMsg)
	}()

	defer pipe.Close()

	// wait until either connection closed
	return <-c
}

func (pipe *pipedConn) Close() {
	pipe.upstream.transport.Close()
	pipe.downstream.transport.Close()
}

func (pipe *pipedConn) pipeAuthSkipBanner(packet []byte) (bool, error) {
	// pipe to auth succ if not a authreq
	// typically, authinfo see RFC 4256
	// TODO support hook this msg
	err := pipe.upstream.transport.writePacket(packet)
	if err != nil {
		return false, err
	}

	for {
		packet, err := pipe.upstream.transport.readPacket()
		if err != nil {
			return false, err
		}

		msgType := packet[0]

		if err = pipe.downstream.transport.writePacket(packet); err != nil {
			return false, err
		}

		switch msgType {
		case msgUserAuthSuccess:
			return true, nil
		case msgUserAuthBanner:
			// should read another packet from upstream
			continue
		case msgUserAuthFailure:
		default:
		}

		return false, nil
	}
}

func (pipe *pipedConn) pipeAuth(initUserAuthMsg *userAuthRequestMsg) error {
	err := pipe.upstream.sendAuthReq()
	if err != nil {
		return err
	}

	userAuthMsg := initUserAuthMsg

	for {
		// hook msg
		userAuthMsg, err = pipe.processAuthMsg(userAuthMsg)

		if err != nil {
			return err
		}

		// nil for ignore
		if userAuthMsg != nil {
			// send a mapped auth msg
			succ, err := pipe.pipeAuthSkipBanner(Marshal(userAuthMsg))

			if err != nil {
				return err
			}

			if succ {
				return nil
			}
		}

		var packet []byte

		for {

			// find next msg which need to be hooked
			if packet, err = pipe.downstream.transport.readPacket(); err != nil {
				return err
			}

			// we can only handle auth req at the moment
			if packet[0] == msgUserAuthRequest {
				// should hook, deal with it
				break
			}

			// pipe other auth msg
			succ, err := pipe.pipeAuthSkipBanner(packet)

			if err != nil {
				return err
			}

			if succ {
				return nil
			}
		}

		var userAuthReq userAuthRequestMsg

		if err = Unmarshal(packet, &userAuthReq); err != nil {
			return err
		}

		userAuthMsg = &userAuthReq
	}
}

func (u *upstream) sendAuthReq() error {
	if err := u.transport.writePacket(Marshal(&serviceRequestMsg{serviceUserAuth})); err != nil {
		return err
	}

	packet, err := u.transport.readPacket()
	if err != nil {
		return err
	}
	var serviceAccept serviceAcceptMsg
	return Unmarshal(packet, &serviceAccept)
}

func newDownstream(c net.Conn, config *ServerConfig) (*downstream, error) {
	fullConf := *config
	fullConf.SetDefaults()

	s := &connection{
		sshConn: sshConn{conn: c},
	}

	_, err := s.serverHandshakeNoAuth(&fullConf)
	if err != nil {
		c.Close()
		return nil, err
	}

	return &downstream{s}, nil
}

func newUpstream(c net.Conn, addr string, config *ClientConfig) (*upstream, error) {
	fullConf := *config
	fullConf.SetDefaults()

	conn := &connection{
		sshConn: sshConn{conn: c},
	}

	if err := conn.clientHandshakeNoAuth(addr, &fullConf); err != nil {
		c.Close()
		return nil, err
	}

	return &upstream{conn}, nil
}

func (d *downstream) nextAuthMsg() (*userAuthRequestMsg, error) {
	var userAuthReq userAuthRequestMsg

	if packet, err := d.transport.readPacket(); err != nil {
		return nil, err
	} else if err = Unmarshal(packet, &userAuthReq); err != nil {
		return nil, err
	}

	if userAuthReq.Service != serviceSSH {
		return nil, errors.New("ssh: client attempted to negotiate for unknown service: " + userAuthReq.Service)
	}

	return &userAuthReq, nil
}

func noneAuthMsg(user string) *userAuthRequestMsg {
	return &userAuthRequestMsg{
		User:    user,
		Service: serviceSSH,
		Method:  "none",
	}
}

func (c *connection) clientHandshakeNoAuth(dialAddress string, config *ClientConfig) error {
	c.clientVersion = []byte(packageVersion)
	if config.ClientVersion != "" {
		c.clientVersion = []byte(config.ClientVersion)
	}

	var err error
	c.serverVersion, err = exchangeVersions(c.sshConn.conn, c.clientVersion)
	if err != nil {
		return err
	}

	c.transport = newClientTransport(
		newTransport(c.sshConn.conn, config.Rand, true /* is client */),
		c.clientVersion, c.serverVersion, config, dialAddress, c.sshConn.RemoteAddr())

	if err := c.transport.waitSession(); err != nil {
		return err
	}

	c.sessionID = c.transport.getSessionID()
	return nil
}

func (c *connection) serverHandshakeNoAuth(config *ServerConfig) (*Permissions, error) {
	if len(config.hostKeys) == 0 {
		return nil, errors.New("ssh: server has no host keys")
	}

	var err error
	if config.ServerVersion != "" {
		c.serverVersion = []byte(config.ServerVersion)
	} else {
		c.serverVersion = []byte("SSH-2.0-SSHPiper")
	}
	c.clientVersion, err = exchangeVersions(c.sshConn.conn, c.serverVersion)
	if err != nil {
		return nil, err
	}

	tr := newTransport(c.sshConn.conn, config.Rand, false /* not client */)
	c.transport = newServerTransport(tr, c.clientVersion, c.serverVersion, config)

	if err := c.transport.waitSession(); err != nil {
		return nil, err

	}
	c.sessionID = c.transport.getSessionID()

	var packet []byte
	if packet, err = c.transport.readPacket(); err != nil {
		return nil, err
	}

	var serviceRequest serviceRequestMsg
	if err = Unmarshal(packet, &serviceRequest); err != nil {
		return nil, err
	}
	if serviceRequest.Service != serviceUserAuth {
		return nil, errors.New("ssh: requested service '" + serviceRequest.Service + "' before authenticating")
	}
	serviceAccept := serviceAcceptMsg{
		Service: serviceUserAuth,
	}
	if err := c.transport.writePacket(Marshal(&serviceAccept)); err != nil {
		return nil, err
	}

	return nil, nil
}
