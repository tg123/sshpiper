package database

import (
	"bytes"
	"encoding/base64"
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
	FromAuthorizedKeys    []authorizedKey
	FromAllowAnyPublicKey bool
	ToType                authMapType
	ToPassword            string
	ToPrivateKey          privateKey
	ToAuthorizedKeys      []authorizedKey
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
		ToAuthorizedKeys:      d.Upstream.AuthorizedKeys,
		NoPassthrough:         d.NoPassthrough,
		KnownHosts:            d.Upstream.KnownHosts,
		IgnoreHostkey:         d.Upstream.Server.IgnoreHostKey,
	}

	return pipe, nil
}

type createPipeCtx struct {
	pipe             pipeConfig
	conn             ssh.ConnMetadata
	challengeContext ssh.AdditionalChallengeContext
}

func (p *plugin) Decode(base64data string, ctx createPipeCtx) ([]byte, error) {

	if base64data != "" {
		//return []byte(base64data), nil
		return base64.StdEncoding.DecodeString(base64data)
	}

	return nil, nil
}

func (p *plugin) createAuthPipe(pipe pipeConfig, conn ssh.ConnMetadata, challengeContext ssh.AdditionalChallengeContext) (*ssh.AuthPipe, error) {

	ctx := createPipeCtx{pipe, conn, challengeContext}

	hostKeyCallback := ssh.InsecureIgnoreHostKey()
	if !pipe.IgnoreHostkey {

		data, err := p.Decode(pipe.KnownHosts, ctx)
		if err != nil {
			return nil, err
		}

		if len(data) == 0 {
			return nil, fmt.Errorf("no known hosts spicified")
		}

		hostKeyCallback, err = knownhosts.NewFromReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
	}

	to := func(key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {

		switch pipe.ToType {
		case authMapTypeNone:
			return ssh.AuthPipeTypeNone, nil, nil

		case authMapTypePassword:
			return ssh.AuthPipeTypeMap, ssh.Password(pipe.ToPassword), nil

		case authMapTypePrivateKey:

			privateBytes, err := p.Decode(pipe.ToPrivateKey.Key.Data, ctx)
			if err != nil {
				return ssh.AuthPipeTypeDiscard, nil, err
			}

			// did not find to 1 private key try key map
			if len(privateBytes) == 0 && key != nil {
				for _, privkey := range pipe.ToAuthorizedKeys {
					rest, err := p.Decode(privkey.Key.Data, ctx)
					if err != nil {
						return ssh.AuthPipeTypeDiscard, nil, err
					}

					var authedPubkey ssh.PublicKey

					for len(rest) > 0 {
						authedPubkey, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
						if err != nil {
							return ssh.AuthPipeTypeDiscard, nil, err
						}

						keydata := key.Marshal()

						if bytes.Equal(authedPubkey.Marshal(), keydata) {
							privateBytes, err = p.Decode(pipe.ToPrivateKey.Key.Data, ctx)

							if err != nil {
								return ssh.AuthPipeTypeDiscard, nil, err
							}

							if len(privateBytes) > 0 {
								// found mapped
								break
							}
						}
					}

				}
			}

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

	allowPasswords := make(map[string]bool)
	var allowPubKeys []ssh.PublicKey
	allowAnyPubKey := false

	a := &ssh.AuthPipe{
		User: pipe.MappedUsername,

		UpstreamHostKeyCallback: hostKeyCallback,
	}

	switch pipe.FromType {
	case authMapTypeNone:

		if a.NoneAuthCallback == nil {
			a.NoneAuthCallback = func(conn ssh.ConnMetadata) (ssh.AuthPipeType, ssh.AuthMethod, error) {
				return to(nil)
			}
		}

	case authMapTypePassword:
		allowPasswords[pipe.FromPassword] = true

		if a.PasswordCallback == nil {
			a.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (ssh.AuthPipeType, ssh.AuthMethod, error) {

				_, ok := allowPasswords[string(password)]

				if ok {
					return to(nil)
				}

				if pipe.NoPassthrough {
					return ssh.AuthPipeTypeDiscard, nil, nil
				}

				return ssh.AuthPipeTypePassThrough, nil, nil
			}
		}

	case authMapTypePrivateKey:

		allowAnyPubKey = allowAnyPubKey || pipe.FromAllowAnyPublicKey

		if !allowAnyPubKey {
			for _, privkey := range pipe.FromAuthorizedKeys {
				rest, err := p.Decode(privkey.Key.Data, ctx)
				if err != nil {
					return nil, err
				}

				var authedPubkey ssh.PublicKey

				for len(rest) > 0 {
					authedPubkey, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
					if err != nil {
						return nil, err
					}

					allowPubKeys = append(allowPubKeys, authedPubkey)
				}
			}
		}

		if a.PublicKeyCallback == nil {
			a.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {

				if allowAnyPubKey {
					return to(key)
				}

				keydata := key.Marshal()

				for _, authedPubkey := range allowPubKeys {
					if bytes.Equal(authedPubkey.Marshal(), keydata) {
						return to(key)
					}
				}

				if pipe.NoPassthrough {
					return ssh.AuthPipeTypeDiscard, nil, nil
				}

				// will fail but discard will lead a timeout
				return ssh.AuthPipeTypePassThrough, nil, nil
			}
		}

	case authMapTypeAny:
		a.NoneAuthCallback = func(conn ssh.ConnMetadata) (ssh.AuthPipeType, ssh.AuthMethod, error) {
			return to(nil)
		}

		a.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (ssh.AuthPipeType, ssh.AuthMethod, error) {
			return to(nil)
		}

		a.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {
			return to(key)
		}

		return a, nil

	default:
		logger.Printf("unsupport type [%v], ignore section", pipe.FromType)
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

	return nil, nil, fmt.Errorf("username not [%v] found", pipe.Username)

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
