package yaml

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"

	"github.com/tg123/sshpiper/sshpiperd/upstream"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"gopkg.in/yaml.v2"
)

type PipeConfig struct {
	Username     string `yaml:"username"`
	UpstreamHost string `yaml:"upstream_host"`
	Authmap      struct {
		MappedUsername string `yaml:"mapped_username"`
		From           []struct {
			Type               string `yaml:"type"`
			Password           string `yaml:"password"`
			AuthorizedKeys     string `yaml:"authorized_keys"`
			AuthorizedKeysData string `yaml:"authorized_keys_data"`
		} `yaml:"from"`

		To struct {
			Type      string `yaml:"type"`
			Password  string `yaml:"password"`
			IDRsa     string `yaml:"id_rsa"`
			IDRsaData string `yaml:"id_rsa_data"`
		} `yaml:"to"`

		NoPassthrough bool `yaml:"no_passthrough"`
	} `yaml:"authmap"`

	KnownHosts     string `yaml:"known_hosts"`
	KnownHostsData string `yaml:"known_hosts_data"`
	IgnoreHostkey  bool   `yaml:"ignore_hostkey"`
}

type PiperConfig struct {
	Version int          `yaml:"version"`
	Pipes   []PipeConfig `yaml:"pipes"`
}

func (p *plugin) loadConfig() (PiperConfig, error) {
	var config PiperConfig

	configbyte, err := ioutil.ReadFile(p.Config.File)
	if err != nil {
		return config, err
	}

	err = yaml.Unmarshal(configbyte, &config)
	if err != nil {
		return config, err
	}

	return config, nil
}

func (p *plugin) createAuthPipe(pipe PipeConfig) (*ssh.AuthPipe, error) {

	hostKeyCallback := ssh.InsecureIgnoreHostKey()
	if !pipe.IgnoreHostkey {
		var err error

		if pipe.KnownHosts != "" {
			hostKeyCallback, err = knownhosts.New(pipe.KnownHosts)
			if err != nil {
				return nil, err
			}

		} else if pipe.KnownHostsData != "" {

			data, err := base64.StdEncoding.DecodeString(pipe.KnownHostsData)
			if err != nil {
				return nil, err
			}

			hostKeyCallback, err = knownhosts.NewFromReader(bytes.NewReader(data))
			if err != nil {
				return nil, err
			}

		}

		return nil, fmt.Errorf("no known hosts spicified")
	}

	to := func() (ssh.AuthPipeType, ssh.AuthMethod, error) {

		switch pipe.Authmap.To.Type {
		case "none":
			return ssh.AuthPipeTypeNone, nil, nil

		case "password":
			return ssh.AuthPipeTypeMap, ssh.Password(pipe.Authmap.To.Password), nil

		case "privatekey":

			privateBytes := []byte(pipe.Authmap.To.IDRsaData)
			if pipe.Authmap.To.IDRsa != "" {
				var err error
				privateBytes, err = ioutil.ReadFile(pipe.Authmap.To.IDRsa)
				if err != nil {
					return ssh.AuthPipeTypeDiscard, nil, err
				}
			} else if pipe.Authmap.To.IDRsaData != "" {
				var err error
				privateBytes, err = base64.StdEncoding.DecodeString(pipe.Authmap.To.IDRsaData)
				if err != nil {
					return ssh.AuthPipeTypeDiscard, nil, err
				}

			} else {
				return ssh.AuthPipeTypeDiscard, nil, fmt.Errorf("no private key found")
			}

			private, err := ssh.ParsePrivateKey(privateBytes)
			if err != nil {
				return ssh.AuthPipeTypeDiscard, nil, err
			}

			return ssh.AuthPipeTypeMap, ssh.PublicKeys(private), nil
		}

		if pipe.Authmap.NoPassthrough {
			return ssh.AuthPipeTypeDiscard, nil, nil
		}

		return ssh.AuthPipeTypePassThrough, nil, nil
	}

	a := &ssh.AuthPipe{
		User: pipe.Authmap.MappedUsername,
		UpstreamHostKeyCallback: hostKeyCallback,
	}

	allowpassword := make(map[string]bool)
	var allowpubkeys []ssh.PublicKey

	for _, from := range pipe.Authmap.From {
		switch from.Type {
		case "none":

			if a.NoneAuthCallback != nil {
				a.NoneAuthCallback = func(conn ssh.ConnMetadata) (ssh.AuthPipeType, ssh.AuthMethod, error) {
					return to()
				}
			}

		case "password":
			allowpassword[from.Password] = true

			if a.PasswordCallback != nil {
				a.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (ssh.AuthPipeType, ssh.AuthMethod, error) {

					_, ok := allowpassword[string(password)]

					if ok {
						return to()
					}

					if pipe.Authmap.NoPassthrough {
						return ssh.AuthPipeTypeDiscard, nil, nil
					}

					return ssh.AuthPipeTypePassThrough, nil, nil
				}
			}

		case "publickey":

			{
				var rest []byte
				var err error

				if from.AuthorizedKeys != "" {
					rest, err = ioutil.ReadFile(from.AuthorizedKeys)
					if err != nil {
						return nil, err
					}
				} else if from.AuthorizedKeysData != "" {
					var err error
					rest, err = base64.StdEncoding.DecodeString(from.AuthorizedKeysData)
					if err != nil {
						return nil, err
					}
				}

				{
					var authedPubkey ssh.PublicKey

					for len(rest) > 0 {
						authedPubkey, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
						if err != nil {
							return nil, err
						}

						allowpubkeys = append(allowpubkeys, authedPubkey)
					}
				}
			}

			if a.PublicKeyCallback != nil {
				a.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {

					keydata := key.Marshal()

					for _, authedPubkey := range allowpubkeys {
						if bytes.Equal(authedPubkey.Marshal(), keydata) {
							return to()
						}
					}

					return ssh.AuthPipeTypeDiscard, nil, nil
				}
			}

		case "any":
			a.NoneAuthCallback = func(conn ssh.ConnMetadata) (ssh.AuthPipeType, ssh.AuthMethod, error) {
				return to()
			}

			a.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (ssh.AuthPipeType, ssh.AuthMethod, error) {
				return to()
			}

			a.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {
				return to()
			}

			return a, nil
		}
	}

	return a, nil
}

func (p *plugin) findUpstream(conn ssh.ConnMetadata, challengeContext ssh.AdditionalChallengeContext) (net.Conn, *ssh.AuthPipe, error) {
	user := conn.User()

	config, err := p.loadConfig()

	if err != nil {
		return nil, nil, err
	}

	for _, pipe := range config.Pipes {
		if pipe.Username == user {

			c, err := upstream.DialForSSH(pipe.UpstreamHost)
			if err != nil {
				return nil, nil, err
			}

			a, err := p.createAuthPipe(pipe)
			if err != nil {
				return nil, nil, err
			}

			return c, a, nil
		}
	}

	return nil, nil, fmt.Errorf("username not [%v] found", user)
}
