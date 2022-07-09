package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"gopkg.in/yaml.v3"
)

type pipeConfigFrom struct {
	Username           string `yaml:"username"`
	UsernameRegexMatch bool   `yaml:"username_regex_match,omitempty"`
	AuthorizedKeys     string `yaml:"authorized_keys,omitempty"`
	AuthorizedKeysData string `yaml:"authorized_keys_data,omitempty"`
}

type pipeConfigTo struct {
	Username       string `yaml:"username,omitempty"`
	Host           string `yaml:"host"`
	Password       string `yaml:"password,omitempty"`
	PrivateKey     string `yaml:"private_key,omitempty"`
	PrivateKeyData string `yaml:"private_key_data,omitempty"`
	KnownHosts     string `yaml:"known_hosts,omitempty"`
	KnownHostsData string `yaml:"known_hosts_data,omitempty"`
	IgnoreHostkey  bool   `yaml:"ignore_hostkey,omitempty"`
}

type pipeConfig struct {
	From []pipeConfigFrom `yaml:"from,flow"`
	To   pipeConfigTo     `yaml:"to,flow"`
}

type piperConfig struct {
	Version string       `yaml:"version"`
	Pipes   []pipeConfig `yaml:"pipes,flow"`
}

type plugin struct {
	File        string
	NoCheckPerm bool

	cache *cache.Cache
}

func newYamlPlugin() *plugin {
	return &plugin{
		cache: cache.New(1*time.Minute, 10*time.Minute),
	}
}

func (p *plugin) checkPerm() error {
	filename := p.File
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}

	if p.NoCheckPerm {
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

	configbyte, err := ioutil.ReadFile(p.File)
	if err != nil {
		return config, err
	}

	err = yaml.Unmarshal(configbyte, &config)
	if err != nil {
		return config, err
	}

	return config, nil
}

func (p *plugin) loadFileOrDecode(file string, base64data string, vars map[string]string) ([]byte, error) {
	if file != "" {

		file = os.Expand(file, func(placeholderName string) string {
			v, ok := vars[placeholderName]
			if ok {
				return v
			}

			return os.Getenv(placeholderName)
		})

		if !filepath.IsAbs(file) {
			file = filepath.Join(filepath.Dir(p.File), file)
		}

		return ioutil.ReadFile(file)
	}

	if base64data != "" {
		return base64.StdEncoding.DecodeString(base64data)
	}

	return nil, nil
}

func (p *plugin) supportedMethods() ([]string, error) {
	config, err := p.loadConfig()
	if err != nil {
		return nil, err
	}

	set := make(map[string]bool)

	for _, pipe := range config.Pipes {
		for _, from := range pipe.From {
			if from.AuthorizedKeys != "" || from.AuthorizedKeysData != "" {
				set["publickey"] = true // found authorized_keys, so we support publickey
			} else {
				set["password"] = true // no authorized_keys, so we support password
			}
		}
	}

	var methods []string
	for k := range set {
		methods = append(methods, k)
	}
	return methods, nil
}

func (p *plugin) verifyHostKey(conn libplugin.ConnMetadata, hostname, netaddr string, key []byte) error {
	item, found := p.cache.Get(conn.UniqueID())

	if !found {
		return fmt.Errorf("connection expired")
	}

	to := item.(*pipeConfigTo)

	data, err := p.loadFileOrDecode(to.KnownHosts, to.KnownHostsData, map[string]string{
		"DOWNSTREAM_USER": conn.User(),
		"UPSTREAM_USER":   to.Username,
	})
	if err != nil {
		return err
	}

	hostKeyCallback, err := knownhosts.NewFromReader(bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	pub, err := ssh.ParsePublicKey(key)
	if err != nil {
		return err
	}

	addr, err := net.ResolveTCPAddr("tcp", netaddr)
	if err != nil {
		return err
	}

	return hostKeyCallback(hostname, addr, pub)
}

func (p *plugin) createUpstream(conn libplugin.ConnMetadata, to pipeConfigTo, originPassword string) (*libplugin.Upstream, error) {

	host, port, err := libplugin.SplitHostPortForSSH(to.Host)
	if err != nil {
		return nil, err
	}

	u := &libplugin.Upstream{
		Host:          host,
		Port:          int32(port),
		UserName:      to.Username,
		IgnoreHostKey: to.IgnoreHostkey,
	}

	pass := to.Password
	if pass == "" {
		pass = originPassword
	}

	// password found
	if pass != "" {
		u.Auth = libplugin.CreatePasswordAuth([]byte(pass))
		return u, p.cache.Add(conn.UniqueID(), &to, cache.DefaultExpiration)
	}

	// try private key
	data, err := p.loadFileOrDecode(to.PrivateKey, to.PrivateKeyData, map[string]string{
		"DOWNSTREAM_USER": conn.User(),
		"UPSTREAM_USER":   to.Username,
	})
	if err != nil {
		return nil, err
	}

	if data != nil {
		u.Auth = libplugin.CreatePrivateKeyAuth(data)
		return u, p.cache.Add(conn.UniqueID(), &to, cache.DefaultExpiration)
	}

	return nil, fmt.Errorf("no password or private key found")
}

func (p *plugin) findAndCreateUpstream(conn libplugin.ConnMetadata, password string, publicKey []byte) (*libplugin.Upstream, error) {
	user := conn.User()

	config, err := p.loadConfig()
	if err != nil {
		return nil, err
	}

	for _, pipe := range config.Pipes {
		for _, from := range pipe.From {
			matched := from.Username == user

			if from.UsernameRegexMatch {
				matched, _ = regexp.MatchString(from.Username, user)
			}

			if !matched {
				continue
			}

			if publicKey == nil {
				return p.createUpstream(conn, pipe.To, password)
			}

			rest, err := p.loadFileOrDecode(from.AuthorizedKeys, from.AuthorizedKeysData, map[string]string{
				"DOWNSTREAM_USER": user,
			})
			if err != nil {
				return nil, err
			}

			var authedPubkey ssh.PublicKey
			for len(rest) > 0 {
				authedPubkey, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
				if err != nil {
					return nil, err
				}

				if bytes.Equal(authedPubkey.Marshal(), publicKey) {
					return p.createUpstream(conn, pipe.To, "")
				}
			}
		}
	}

	return nil, fmt.Errorf("no matching pipe for username [%v] found", user)
}
