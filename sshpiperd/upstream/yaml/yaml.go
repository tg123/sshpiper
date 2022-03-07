package yaml

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"

	"github.com/tg123/sshpiper/sshpiperd/upstream"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"gopkg.in/yaml.v3"
)

type pipeConfig struct {
	Username           string `yaml:"username"`
	UsernameRegexMatch bool   `yaml:"username_regex_match,omitempty"`
	UpstreamHost       string `yaml:"upstream_host"`
	Authmap            struct {
		MappedUsername string `yaml:"mapped_username,omitempty"`
		From           []struct {
			Type               string `yaml:"type"`
			Password           string `yaml:"password,omitempty"`
			AuthorizedKeys     string `yaml:"authorized_keys,omitempty"`
			AuthorizedKeysData string `yaml:"authorized_keys_data,omitempty"`
			AllowAnyPublicKey  bool   `yaml:"allow_any_public_key,omitempty"`
		} `yaml:"from,flow"`

		To struct {
			Type           string `yaml:"type"`
			Password       string `yaml:"password,omitempty"`
			PrivateKey     string `yaml:"private_key,omitempty"`
			PrivateKeyData string `yaml:"private_key_data,omitempty"`
			KeyMap         []struct {
				AuthorizedKeys     string `yaml:"authorized_keys,omitempty"`
				AuthorizedKeysData string `yaml:"authorized_keys_data,omitempty"`
				PrivateKey         string `yaml:"private_key,omitempty"`
				PrivateKeyData     string `yaml:"private_key_data,omitempty"`
			} `yaml:"key_map,flow"`
		} `yaml:"to,flow"`

		NoPassthrough bool `yaml:"no_passthrough,omitempty"`
	} `yaml:"authmap,omitempty,flow"`

	KnownHosts     string `yaml:"known_hosts,omitempty"`
	KnownHostsData string `yaml:"known_hosts_data,omitempty"`
	IgnoreHostkey  bool   `yaml:"ignore_hostkey,omitempty"`
}

type piperConfig struct {
	Version int          `yaml:"version"`
	Pipes   []pipeConfig `yaml:"pipes,flow"`
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

func (p *plugin) loadConfig() (piperConfig, error) {
	var config piperConfig

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

type createPipeCtx struct {
	pipe             pipeConfig
	conn             ssh.ConnMetadata
	challengeContext ssh.AdditionalChallengeContext
}

func (p *plugin) loadFileOrDecode(file string, base64data string, ctx createPipeCtx) ([]byte, error) {
	if file != "" {

		file = os.Expand(file, func(placeholderName string) string {
			switch placeholderName {
			case "USER":
				return ctx.conn.User()
			case "MAPPED_USER":
				return ctx.pipe.Authmap.MappedUsername
			}

			return os.Getenv(placeholderName)
		})

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

func (p *plugin) createAuthPipe(pipe pipeConfig, conn ssh.ConnMetadata, challengeContext ssh.AdditionalChallengeContext) (*ssh.AuthPipe, error) {
	ctx := createPipeCtx{pipe, conn, challengeContext}

	hostKeyCallback := ssh.InsecureIgnoreHostKey()
	if !pipe.IgnoreHostkey {

		data, err := p.loadFileOrDecode(pipe.KnownHosts, pipe.KnownHostsData, ctx)
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

		switch pipe.Authmap.To.Type {
		case "none":
			return ssh.AuthPipeTypeNone, nil, nil

		case "password":
			return ssh.AuthPipeTypeMap, ssh.Password(pipe.Authmap.To.Password), nil

		case "privatekey":

			privateBytes, err := p.loadFileOrDecode(pipe.Authmap.To.PrivateKey, pipe.Authmap.To.PrivateKeyData, ctx)
			if err != nil {
				return ssh.AuthPipeTypeDiscard, nil, err
			}

			// did not find to 1 private key try key map
			if len(privateBytes) == 0 && key != nil {
				for _, privkey := range pipe.Authmap.To.KeyMap {
					rest, err := p.loadFileOrDecode(privkey.AuthorizedKeys, privkey.AuthorizedKeysData, ctx)
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
							privateBytes, err = p.loadFileOrDecode(privkey.PrivateKey, privkey.PrivateKeyData, ctx)

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
			p.logger.Printf("unsupport type [%v] fallback to passthrough", pipe.Authmap.To.Type)
		}

		if pipe.Authmap.NoPassthrough {
			return ssh.AuthPipeTypeDiscard, nil, nil
		}

		return ssh.AuthPipeTypePassThrough, nil, nil
	}

	allowPasswords := make(map[string]bool)
	var allowPubKeys []ssh.PublicKey
	allowAnyPubKey := false

	a := &ssh.AuthPipe{
		User: pipe.Authmap.MappedUsername,

		UpstreamHostKeyCallback: hostKeyCallback,
	}

	for _, from := range pipe.Authmap.From {
		switch from.Type {
		case "none":

			if a.NoneAuthCallback == nil {
				a.NoneAuthCallback = func(conn ssh.ConnMetadata) (ssh.AuthPipeType, ssh.AuthMethod, error) {
					return to(nil)
				}
			}

		case "password":
			allowPasswords[from.Password] = true

			if a.PasswordCallback == nil {
				a.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (ssh.AuthPipeType, ssh.AuthMethod, error) {

					_, ok := allowPasswords[string(password)]

					if ok {
						return to(nil)
					}

					if pipe.Authmap.NoPassthrough {
						return ssh.AuthPipeTypeDiscard, nil, nil
					}

					return ssh.AuthPipeTypePassThrough, nil, nil
				}
			}

		case "publickey":

			allowAnyPubKey = allowAnyPubKey || from.AllowAnyPublicKey

			if !allowAnyPubKey {

				rest, err := p.loadFileOrDecode(from.AuthorizedKeys, from.AuthorizedKeysData, ctx)
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

					if pipe.Authmap.NoPassthrough {
						return ssh.AuthPipeTypeDiscard, nil, nil
					}

					// will fail but discard will lead a timeout
					return ssh.AuthPipeTypePassThrough, nil, nil
				}
			}

		case "any":
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
		matched := pipe.Username == user

		if pipe.UsernameRegexMatch {
			matched, _ = regexp.MatchString(pipe.Username, user)
		}

		if matched {

			p.logger.Printf("mapping [%v] to [%v@%v]", user, pipe.Authmap.MappedUsername, pipe.UpstreamHost)

			c, err := upstream.DialForSSH(pipe.UpstreamHost)
			if err != nil {
				return nil, nil, err
			}

			a, err := p.createAuthPipe(pipe, conn, challengeContext)
			if err != nil {
				return nil, nil, err
			}

			return c, a, nil
		}
	}

	return nil, nil, fmt.Errorf("username [%v] not found", user)
}
