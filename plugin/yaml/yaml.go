//go:build full || e2e

package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

type pipeConfigFrom struct {
	Username           string       `yaml:"username"`
	UsernameRegexMatch bool         `yaml:"username_regex_match,omitempty"`
	AuthorizedKeys     listOrString `yaml:"authorized_keys,omitempty"`
	AuthorizedKeysData listOrString `yaml:"authorized_keys_data,omitempty"`
}

type pipeConfigTo struct {
	Username       string       `yaml:"username,omitempty"`
	Host           string       `yaml:"host"`
	Password       string       `yaml:"password,omitempty"`
	PrivateKey     string       `yaml:"private_key,omitempty"`
	PrivateKeyData string       `yaml:"private_key_data,omitempty"`
	KnownHosts     listOrString `yaml:"known_hosts,omitempty"`
	KnownHostsData listOrString `yaml:"known_hosts_data,omitempty"`
	IgnoreHostkey  bool         `yaml:"ignore_hostkey,omitempty"`
}

type listOrString struct {
	List []string
	Str  string
}

func (l *listOrString) Any() bool {
	return len(l.List) > 0 || l.Str != ""
}

func (l *listOrString) Combine() []string {
	if l.Str != "" {
		return append(l.List, l.Str)
	}
	return l.List
}

func (l *listOrString) UnmarshalYAML(value *yaml.Node) error {
	// Try to unmarshal as a list
	var list []string
	if err := value.Decode(&list); err == nil {
		l.List = list
		return nil
	}
	// Try to unmarshal as a string
	var str string
	if err := value.Decode(&str); err == nil {
		l.Str = str
		return nil
	}
	return fmt.Errorf("Failed to unmarshal OneOfType")
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

	configbyte, err := os.ReadFile(p.File)
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

		return os.ReadFile(file)
	}

	if base64data != "" {
		return base64.StdEncoding.DecodeString(base64data)
	}

	return nil, nil
}

func (p *plugin) loadFileOrDecodeMany(files listOrString, base64data listOrString, vars map[string]string) ([]byte, error) {
	var byteSlices [][]byte

	for _, file := range files.Combine() {
		data, err := p.loadFileOrDecode(file, "", vars)
		if err != nil {
			return nil, err
		}

		if data != nil {
			byteSlices = append(byteSlices, data)
		}
	}

	for _, data := range base64data.Combine() {
		decoded, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			return nil, err
		}

		if decoded != nil {
			byteSlices = append(byteSlices, decoded)
		}
	}

	return bytes.Join(byteSlices, []byte("\n")), nil
}

func (p *plugin) supportedMethods() ([]string, error) {
	config, err := p.loadConfig()
	if err != nil {
		return nil, err
	}

	set := make(map[string]bool)

	for _, pipe := range config.Pipes {
		for _, from := range pipe.From {
			if from.AuthorizedKeys.Any() || from.AuthorizedKeysData.Any() {
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

	data, err := p.loadFileOrDecodeMany(to.KnownHosts, to.KnownHostsData, map[string]string{
		"DOWNSTREAM_USER": conn.User(),
		"UPSTREAM_USER":   to.Username,
	})
	if err != nil {
		return err
	}

	return libplugin.VerifyHostKeyFromKnownHosts(bytes.NewBuffer(data), hostname, netaddr, key)
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
		p.cache.Set(conn.UniqueID(), &to, cache.DefaultExpiration)
		return u, nil
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
		p.cache.Set(conn.UniqueID(), &to, cache.DefaultExpiration)
		return u, nil
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

			if pipe.To.Username == "" {
				pipe.To.Username = user
			}

			if from.UsernameRegexMatch {
				re, err := regexp.Compile(from.Username)
				if err != nil {
					return nil, err
				}

				matched = re.MatchString(user)

				if matched {
					pipe.To.Username = re.ReplaceAllString(user, pipe.To.Username)
				}
			}

			if !matched {
				continue
			}

			if publicKey == nil && password != "" {
				return p.createUpstream(conn, pipe.To, password)
			}

			rest, err := p.loadFileOrDecodeMany(from.AuthorizedKeys, from.AuthorizedKeysData, map[string]string{
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

				if subtle.ConstantTimeCompare(authedPubkey.Marshal(), publicKey) == 1 {
					return p.createUpstream(conn, pipe.To, "")
				}
			}
		}
	}

	return nil, fmt.Errorf("no matching pipe for username [%v] found", user)
}
