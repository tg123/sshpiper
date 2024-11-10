package libplugin

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/patrickmn/go-cache"
	"golang.org/x/crypto/ssh"

	log "github.com/sirupsen/logrus"
)

type SkelPlugin struct {
	cache    *cache.Cache
	listPipe func(ConnMetadata) ([]SkelPipe, error)
}

func NewSkelPlugin(listPipe func(ConnMetadata) ([]SkelPipe, error)) *SkelPlugin {
	return &SkelPlugin{
		cache:    cache.New(1*time.Minute, 10*time.Minute),
		listPipe: listPipe,
	}
}

type SkelPipe interface {
	From() []SkelPipeFrom
}

type SkelPipeFrom interface {
	MatchConn(conn ConnMetadata) (SkelPipeTo, error)
}

type SkelPipeFromPassword interface {
	SkelPipeFrom

	TestPassword(conn ConnMetadata, password []byte) (bool, error)
}

type SkelPipeFromPublicKey interface {
	SkelPipeFrom

	AuthorizedKeys(conn ConnMetadata) ([]byte, error)
	TrustedUserCAKeys(conn ConnMetadata) ([]byte, error)
}

type SkelPipeTo interface {
	Host(conn ConnMetadata) string
	User(conn ConnMetadata) string
	IgnoreHostKey(conn ConnMetadata) bool
	KnownHosts(conn ConnMetadata) ([]byte, error)
}

type SkelPipeToPassword interface {
	SkelPipeTo

	OverridePassword(conn ConnMetadata) ([]byte, error)
}

type SkelPipeToPrivateKey interface {
	SkelPipeTo

	PrivateKey(conn ConnMetadata) ([]byte, []byte, error)
}

func (p *SkelPlugin) CreateConfig() *SshPiperPluginConfig {
	return &SshPiperPluginConfig{
		NextAuthMethodsCallback: p.SupportedMethods,
		PasswordCallback:        p.PasswordCallback,
		PublicKeyCallback:       p.PublicKeyCallback,
		VerifyHostKeyCallback:   p.VerifyHostKeyCallback,
	}
}

func (p *SkelPlugin) SupportedMethods(conn ConnMetadata) ([]string, error) {
	set := make(map[string]bool)

	pipes, err := p.listPipe(conn)
	if err != nil {
		return nil, err
	}

	for _, pipe := range pipes {
		for _, from := range pipe.From() {

			switch from.(type) {
			case SkelPipeFromPublicKey:
				set["publickey"] = true
			default:
				set["password"] = true
			}

			if len(set) == 2 {
				break
			}
		}
	}

	var methods []string
	for k := range set {
		methods = append(methods, k)
	}

	return methods, nil
}

func (p *SkelPlugin) VerifyHostKeyCallback(conn ConnMetadata, hostname, netaddr string, key []byte) error {
	item, found := p.cache.Get(conn.UniqueID())
	if !found {
		log.Warnf("connection expired when verifying host key for conn [%v]", conn.UniqueID())
		return fmt.Errorf("connection expired")
	}

	to := item.(SkelPipeTo)

	data, err := to.KnownHosts(conn)
	if err != nil {
		return err
	}

	return VerifyHostKeyFromKnownHosts(bytes.NewBuffer(data), hostname, netaddr, key)
}

func (p *SkelPlugin) match(conn ConnMetadata, verify func(SkelPipeFrom) (bool, error)) (SkelPipeFrom, SkelPipeTo, error) {
	pipes, err := p.listPipe(conn)
	if err != nil {
		return nil, nil, err
	}

	for _, pipe := range pipes {
		for _, from := range pipe.From() {

			to, err := from.MatchConn(conn)
			if err != nil {
				return nil, nil, err
			}

			if to == nil {
				continue
			}

			ok, err := verify(from)
			if err != nil {
				return nil, nil, err
			}

			if ok {
				return from, to, nil
			}
		}
	}

	return nil, nil, fmt.Errorf("no matching pipe for username [%v] found", conn.User())
}

func (p *SkelPlugin) PasswordCallback(conn ConnMetadata, password []byte) (*Upstream, error) {
	_, to, err := p.match(conn, func(from SkelPipeFrom) (bool, error) {
		frompass, ok := from.(SkelPipeFromPassword)

		if !ok {
			return false, nil
		}

		return frompass.TestPassword(conn, password)
	})
	if err != nil {
		return nil, err
	}

	u, err := p.createUpstream(conn, to, password)
	if err != nil {
		return nil, err
	}

	return u, nil
}

func (p *SkelPlugin) PublicKeyCallback(conn ConnMetadata, publicKey []byte) (*Upstream, error) {

	pubKey, err := ssh.ParsePublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	pkcert, isCert := pubKey.(*ssh.Certificate)
	if isCert {
		// ensure cert is valid first

		if pkcert.CertType != ssh.UserCert {
			return nil, fmt.Errorf("only user certificates are supported, cert type: %v", pkcert.CertType)
		}

		certChecker := ssh.CertChecker{}
		if err := certChecker.CheckCert(conn.User(), pkcert); err != nil {
			return nil, err
		}
	}

	_, to, err := p.match(conn, func(from SkelPipeFrom) (bool, error) {
		// verify public key
		fromPubKey, ok := from.(SkelPipeFromPublicKey)
		if !ok {
			return false, nil
		}

		verified := false

		if isCert {
			rest, err := fromPubKey.TrustedUserCAKeys(conn)
			if err != nil {
				return false, err
			}

			log.Debugf("trusted user ca keys: %v", rest)

			var trustedca ssh.PublicKey
			for len(rest) > 0 {
				trustedca, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
				if err != nil {
					return false, err
				}

				if subtle.ConstantTimeCompare(trustedca.Marshal(), pkcert.SignatureKey.Marshal()) == 1 {
					verified = true
					break
				}
			}
		} else {
			rest, err := fromPubKey.AuthorizedKeys(conn)
			if err != nil {
				return false, err
			}

			var authedPubkey ssh.PublicKey
			for len(rest) > 0 {
				authedPubkey, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
				if err != nil {
					return false, err
				}

				if subtle.ConstantTimeCompare(authedPubkey.Marshal(), publicKey) == 1 {
					verified = true
					break
				}
			}
		}

		return verified, nil
	})

	if err != nil {
		return nil, err
	}

	u, err := p.createUpstream(conn, to, nil)
	if err != nil {
		return nil, err
	}

	return u, nil
}

func (p *SkelPlugin) createUpstream(conn ConnMetadata, to SkelPipeTo, originalPassword []byte) (*Upstream, error) {
	host, port, err := SplitHostPortForSSH(to.Host(conn))
	if err != nil {
		return nil, err
	}

	user := to.User(conn)
	if user == "" {
		user = conn.User()
	}

	p.cache.SetDefault(conn.UniqueID(), to)

	u := &Upstream{
		Host:          host,
		Port:          int32(port), // port is already checked to be within int32 range in SplitHostPortForSSH
		UserName:      user,
		IgnoreHostKey: to.IgnoreHostKey(conn),
	}

	switch to := to.(type) {
	case SkelPipeToPassword:
		overridepassword, err := to.OverridePassword(conn)
		if err != nil {
			return nil, err
		}

		if overridepassword != nil {
			u.Auth = CreatePasswordAuth(overridepassword)
		} else {
			u.Auth = CreatePasswordAuth(originalPassword)
		}

	case SkelPipeToPrivateKey:
		priv, cert, err := to.PrivateKey(conn)
		if err != nil {
			return nil, err
		}

		u.Auth = CreatePrivateKeyAuth(priv, cert)
	default:
		return nil, fmt.Errorf("pipe to does not support any auth method")
	}

	return u, err
}
