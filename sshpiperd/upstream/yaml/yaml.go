package yaml

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	"github.com/tg123/sshpiper/sshpiperd/upstream"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"gopkg.in/yaml.v3"
)

type PipeConfig struct {
	Username     string `yaml:"username"`
	UpstreamHost string `yaml:"upstream_host"`
	Authmap      struct {
		MappedUsername string `yaml:"mapped_username,omitempty"`
		From           []struct {
			Type               string `yaml:"type"`
			Password           string `yaml:"password,omitempty"`
			AuthorizedKeys     string `yaml:"authorized_keys,omitempty"`
			AuthorizedKeysData string `yaml:"authorized_keys_data,omitempty"`
		} `yaml:"from,flow"`

		To struct {
			Type      string `yaml:"type"`
			Password  string `yaml:"password,omitempty"`
			IDRsa     string `yaml:"id_rsa,omitempty"`
			IDRsaData string `yaml:"id_rsa_data,omitempty"`

			// KeyMapFile map[string]string `yaml:"key_map_file,omitempty,flow"`
			// KeyMapData map[string]string `yaml:"key_map_data,omitempty,flow"`
		} `yaml:"to,flow"`

		NoPassthrough bool `yaml:"no_passthrough,omitempty"`
	} `yaml:"authmap,omitempty,flow"`

	KnownHosts     string `yaml:"known_hosts,omitempty"`
	KnownHostsData string `yaml:"known_hosts_data,omitempty"`
	IgnoreHostkey  bool   `yaml:"ignore_hostkey,omitempty"`
}

type PiperConfig struct {
	Version int          `yaml:"version"`
	Pipes   []PipeConfig `yaml:"pipes,flow"`
}

func (p *plugin) checkPerm() error {
	filename := p.Config.File
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}

	if p.Config.NoCheckPerm {
		return nil
	}

	if fi.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%v's perm is too open", filename)
	}

	return nil
}

func (p *plugin) loadConfig() (PiperConfig, error) {
	var config PiperConfig

	err := p.checkPerm()

	if err != nil {
		return config, err
	}

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

func (p *plugin) loadFileOrDecode(file string, base64data string) ([]byte, error) {
	if file != "" {

		if !filepath.IsAbs(file) {
			file = filepath.Join(filepath.Dir(p.Config.File), file)
		}

		return ioutil.ReadFile(file)
	}

	if base64data != "" {
		return base64.StdEncoding.DecodeString(base64data)
	}

	return nil, nil
}

func (p *plugin) createAuthPipe(pipe PipeConfig) (*ssh.AuthPipe, error) {

	hostKeyCallback := ssh.InsecureIgnoreHostKey()
	if !pipe.IgnoreHostkey {

		data, err := p.loadFileOrDecode(pipe.KnownHosts, pipe.KnownHostsData)
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

	to := func() (ssh.AuthPipeType, ssh.AuthMethod, error) {

		switch pipe.Authmap.To.Type {
		case "none":
			return ssh.AuthPipeTypeNone, nil, nil

		case "password":
			return ssh.AuthPipeTypeMap, ssh.Password(pipe.Authmap.To.Password), nil

		case "privatekey":

			privateBytes, err := p.loadFileOrDecode(pipe.Authmap.To.IDRsa, pipe.Authmap.To.IDRsaData)
			if err != nil {
				return ssh.AuthPipeTypeDiscard, nil, err
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
			p.logger.Printf("unsupport type [%v] fallback to passthrough", pipe.Authmap.To.Type)
		}

		if pipe.Authmap.NoPassthrough {
			return ssh.AuthPipeTypeDiscard, nil, nil
		}

		return ssh.AuthPipeTypePassThrough, nil, nil
	}

	a := &ssh.AuthPipe{
		User:                    pipe.Authmap.MappedUsername,
		UpstreamHostKeyCallback: hostKeyCallback,
	}

	allowpassword := make(map[string]bool)
	var allowpubkeys []ssh.PublicKey

	for _, from := range pipe.Authmap.From {
		switch from.Type {
		case "none":

			if a.NoneAuthCallback == nil {
				a.NoneAuthCallback = func(conn ssh.ConnMetadata) (ssh.AuthPipeType, ssh.AuthMethod, error) {
					return to()
				}
			}

		case "password":
			allowpassword[from.Password] = true

			if a.PasswordCallback == nil {
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
				rest, err := p.loadFileOrDecode(from.AuthorizedKeys, from.AuthorizedKeysData)
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

			if a.PublicKeyCallback == nil {
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

		default:
			p.logger.Printf("unsupport type [%v], ignore section", from.Type)
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
