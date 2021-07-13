package database

import (
	"bytes"
	"fmt"
	"net"

	"github.com/jinzhu/gorm"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	upstreamprovider "github.com/tg123/sshpiper/sshpiperd/upstream"
)

type pipeConfig struct {
	Username              string
	UpstreamHost          string
	MappedUsername        string
	FromType              authMapType
	FromPassword          string
	FromPrivateKey        keydata
	FromAuthorizedKeys    keydata
	FromAllowAnyPublicKey bool
	ToType                authMapType
	ToPassword            string
	ToPrivateKey          keydata
	ToAuthorizedKeys      keydata
	NoPassthrough         bool
	KnownHosts            string
	KnownHostsData        string
	IgnoreHostkey         bool
}

func (p *plugin) loadPipeFromDB(conn ssh.ConnMetadata) (pipeConfig, error) {

	user := conn.User()
	d, err := lookupDownstreamWithFallback(p.db, user)

	if err != nil {
		return pipeConfig{}, err
	}

	pipe := pipeConfig{
		Username:              user,
		UpstreamHost:          d.Upstream.Server.Address,
		MappedUsername:        d.Upstream.Username,
		FromType:              d.AuthMapType,
		FromPassword:          d.Password,
		FromAuthorizedKeys:    d.AuthorizedKeys,
		FromAllowAnyPublicKey: d.AllowAnyPublicKey,
		ToType:                d.Upstream.AuthMapType,
		ToPassword:            d.Upstream.Password,
		ToPrivateKey:          d.Upstream.PrivateKey,
		NoPassthrough:         d.NoPassthrough,
		KnownHosts:            d.Upstream.KnownHosts,
		IgnoreHostkey:         d.Upstream.Server.IgnoreHostKey,
	}

	return pipe, nil
}

func (p *plugin) createAuthPipe(pipe pipeConfig, conn ssh.ConnMetadata, challengeContext ssh.AdditionalChallengeContext) (*ssh.AuthPipe, error) {

	hostKeyCallback := ssh.InsecureIgnoreHostKey()
	if !pipe.IgnoreHostkey {

		var err error
		data := []byte(pipe.KnownHosts)

		if len(data) == 0 {
			return nil, fmt.Errorf("no known hosts specified")
		}

		hostKeyCallback, err = knownhosts.NewFromReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
	}

	to := func() (ssh.AuthPipeType, ssh.AuthMethod, error) {
		switch pipe.ToType {
		case authMapTypeNone:
			return ssh.AuthPipeTypeNone, nil, nil

		case authMapTypePassword:
			return ssh.AuthPipeTypeMap, ssh.Password(pipe.ToPassword), nil

		case authMapTypePrivateKey:
			privateBytes := []byte(pipe.ToPrivateKey.Data)

			if len(privateBytes) == 0 {
				return ssh.AuthPipeTypeDiscard, nil, fmt.Errorf("no private key found")
			}

			private, err := ssh.ParsePrivateKey(privateBytes)
			if err != nil {
				return ssh.AuthPipeTypeDiscard, nil, err
			}

			return ssh.AuthPipeTypeMap, ssh.PublicKeys(private), nil

		default:
			logger.Printf("unsupport type [%v] fallback to passthrough", pipe.ToType)
		}

		if pipe.NoPassthrough {
			return ssh.AuthPipeTypeDiscard, nil, nil
		}

		return ssh.AuthPipeTypePassThrough, nil, nil
	}

	a := &ssh.AuthPipe{
		User:                    pipe.MappedUsername,
		UpstreamHostKeyCallback: hostKeyCallback,
	}

	noneauth := func(conn ssh.ConnMetadata) (ssh.AuthPipeType, ssh.AuthMethod, error) {
		return to()
	}

	passauth := func(conn ssh.ConnMetadata, password []byte) (ssh.AuthPipeType, ssh.AuthMethod, error) {
		if string(password) == pipe.FromPassword {
			return to()
		}

		if pipe.NoPassthrough {
			return ssh.AuthPipeTypeDiscard, nil, nil
		}

		return ssh.AuthPipeTypePassThrough, nil, nil
	}

	var allowPubKeys []ssh.PublicKey
	allowAnyPubKey := pipe.FromAllowAnyPublicKey
	if !allowAnyPubKey {
		var err error
		rest := []byte(pipe.FromAuthorizedKeys.Data)

		var authedPubkey ssh.PublicKey

		for len(rest) > 0 {
			authedPubkey, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
			if err != nil {
				return nil, err
			}

			allowPubKeys = append(allowPubKeys, authedPubkey)
		}
	}

	keyuath := func(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {

		if allowAnyPubKey {
			return to()
		}

		keydata := key.Marshal()

		for _, authedPubkey := range allowPubKeys {
			if bytes.Equal(authedPubkey.Marshal(), keydata) {
				return to()
			}
		}

		if pipe.NoPassthrough {
			return ssh.AuthPipeTypeDiscard, nil, nil
		}

		// will fail but discard will lead a timeout
		return ssh.AuthPipeTypePassThrough, nil, nil
	}

	switch pipe.FromType {
	case authMapTypeNone:
		a.NoneAuthCallback = noneauth

	case authMapTypePassword:
		a.PasswordCallback = passauth

	case authMapTypePrivateKey:
		a.PublicKeyCallback = keyuath

	case authMapTypeAny:
		a.NoneAuthCallback = noneauth
		a.PasswordCallback = passauth
		a.PublicKeyCallback = keyuath

	default:
		return nil, fmt.Errorf("unsupported auth type [%v],", pipe.FromType)
	}

	return a, nil

}

func (p *plugin) findUpstream(conn ssh.ConnMetadata, challengeContext ssh.AdditionalChallengeContext) (net.Conn, *ssh.AuthPipe, error) {

	pipe, err := p.loadPipeFromDB(conn)
	if err != nil {
		return nil, nil, err
	}

	if pipe.Username != "" {

		logger.Printf("mapping [%v] to [%v@%v] from %v to %v", pipe.Username, pipe.MappedUsername, pipe.UpstreamHost, pipe.FromType, pipe.ToType)

		c, err := upstreamprovider.DialForSSH(pipe.UpstreamHost)
		if err != nil {
			return nil, nil, err
		}
		a, err := p.createAuthPipe(pipe, conn, challengeContext)
		if err != nil {
			return nil, nil, err
		}
		return c, a, nil
	}

	return nil, nil, fmt.Errorf("username should not be empty")

}

func lookupDownstreamWithFallback(db *gorm.DB, user string) (*downstream, error) {
	d, err := lookupDownstream(db, user)

	if gorm.IsRecordNotFoundError(err) {
		fallback, _ := lookupConfigValue(db, fallbackUserEntry)

		if len(fallback) > 0 {
			return lookupDownstream(db, fallback)
		}
	}

	return d, err
}

func lookupDownstream(db *gorm.DB, user string) (*downstream, error) {
	d := downstream{}

	if err := db.Set("gorm:auto_preload", true).Where(&downstream{Username: user}).First(&d).Error; err != nil {

		return nil, err
	}

	return &d, nil
}

func lookupConfigValue(db *gorm.DB, entry string) (string, error) {
	c := config{}
	if err := db.Where(&config{Entry: entry}).First(&c).Error; err != nil {
		return "", err
	}

	return c.Value, nil
}
