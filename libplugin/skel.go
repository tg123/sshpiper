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

type SkelPluginAuthMethod int

const (
	SkelPluginAuthMethodNone = 1 << iota
	SkelPluginAuthMethodPassword
	SkelPluginAuthMethodPublicKey
)

const SkelPluginAuthMethodAll SkelPluginAuthMethod = SkelPluginAuthMethodPassword | SkelPluginAuthMethodPublicKey | SkelPluginAuthMethodNone

type SkelPlugin struct {
	cache    *cache.Cache
	listPipe func() ([]SkelPipe, error)
}

func NewSkelPlugin(listPipe func() ([]SkelPipe, error)) *SkelPlugin {
	return &SkelPlugin{
		cache:    cache.New(1*time.Minute, 10*time.Minute),
		listPipe: listPipe,
	}
}

type SkelPipe interface {
	From() []SkelPipeFrom
}

type SkelPipeFrom interface {
	Match(conn ConnMetadata) (SkelPipeTo, error)
}

type SkelPipeFromPassword interface {
	SkelPipeFrom
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
}

type SkelPipeToPrivateKey interface {
	SkelPipeTo

	PrivateKey(conn ConnMetadata) ([]byte, error)

	// Certificate() ([]byte, error) TODO support later
}

func (p *SkelPlugin) CreateConfig() *SshPiperPluginConfig {
	return &SshPiperPluginConfig{
		NextAuthMethodsCallback: p.SupportedMethods,
		PasswordCallback:        p.PasswordCallback,
		PublicKeyCallback:       p.PublicKeyCallback,
		VerifyHostKeyCallback:   p.VerifyHostKeyCallback,
	}
}

func (p *SkelPlugin) SupportedMethods(_ ConnMetadata) ([]string, error) {
	set := make(map[string]bool)

	pipes, err := p.listPipe()
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

func (p *SkelPlugin) match(conn ConnMetadata, filter SkelPluginAuthMethod) (SkelPipeFrom, SkelPipeTo, error) {
	pipes, err := p.listPipe()
	if err != nil {
		return nil, nil, err
	}

	for _, pipe := range pipes {
		for _, from := range pipe.From() {

			switch from.(type) {
			case SkelPipeFromPublicKey:
				if filter&SkelPluginAuthMethodPublicKey == 0 {
					continue
				}
			default:
				if filter&SkelPluginAuthMethodPassword == 0 {
					continue
				}
			}

			to, err := from.Match(conn)
			if err != nil {
				return nil, nil, err
			}

			if to != nil {
				return from, to, nil
			}
		}
	}

	return nil, nil, fmt.Errorf("no matching pipe for username [%v] found using auth [%v]", conn.User(), filter)
}

func (p *SkelPlugin) PasswordCallback(conn ConnMetadata, password []byte) (*Upstream, error) {
	_, to, err := p.match(conn, SkelPluginAuthMethodPassword)
	if err != nil {
		return nil, err
	}

	u, err := p.createUpstream(conn, to)
	if err != nil {
		return nil, err
	}

	u.Auth = CreatePasswordAuth(password)
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

	from, to, err := p.match(conn, SkelPluginAuthMethodPublicKey)
	if err != nil {
		return nil, err
	}

	fromPubKey, ok := from.(SkelPipeFromPublicKey)
	if !ok {
		return nil, fmt.Errorf("pipe from does not support public key")
	}

	// verify public key

	verified := false

	if isCert {
		rest, err := fromPubKey.TrustedUserCAKeys(conn)
		if err != nil {
			return nil, err
		}

		log.Debugf("trusted user ca keys: %v", rest)

		var trustedca ssh.PublicKey
		for len(rest) > 0 {
			trustedca, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
			if err != nil {
				return nil, err
			}

			if subtle.ConstantTimeCompare(trustedca.Marshal(), pkcert.SignatureKey.Marshal()) == 1 {
				verified = true
				break
			}
		}
	} else {
		rest, err := fromPubKey.AuthorizedKeys(conn)
		if err != nil {
			return nil, err
		}

		var authedPubkey ssh.PublicKey
		for len(rest) > 0 {
			authedPubkey, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
			if err != nil {
				return nil, err
			}

			if subtle.ConstantTimeCompare(authedPubkey.Marshal(), publicKey) == 1 {
				verified = true
				break
			}
		}
	}

	if !verified {
		return nil, fmt.Errorf("public key verification failed")
	}

	u, err := p.createUpstream(conn, to)
	if err != nil {
		return nil, err
	}

	toPrivateKey, ok := to.(SkelPipeToPrivateKey)
	if !ok {
		return nil, fmt.Errorf("pipe to does not support private key")
	}

	priv, err := toPrivateKey.PrivateKey(conn)
	if err != nil {
		return nil, err
	}

	u.Auth = CreatePrivateKeyAuth(priv)

	return u, nil
}

func (p *SkelPlugin) createUpstream(conn ConnMetadata, to SkelPipeTo) (*Upstream, error) {
	host, port, err := SplitHostPortForSSH(to.Host(conn))
	if err != nil {
		return nil, err
	}

	user := to.User(conn)
	if user == "" {
		user = conn.User()
	}

	p.cache.SetDefault(conn.UniqueID(), to)

	return &Upstream{
		Host:          host,
		Port:          int32(port),
		UserName:      user,
		IgnoreHostKey: to.IgnoreHostKey(conn),
	}, err
}
