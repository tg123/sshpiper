//go:build full || e2e

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/tg123/sshpiper/libplugin"
	"gopkg.in/yaml.v3"
)

type yamlPipeFrom struct {
	Username              string       `yaml:"username"`
	UsernameRegexMatch    bool         `yaml:"username_regex_match,omitempty"`
	AuthorizedKeys        listOrString `yaml:"authorized_keys,omitempty"`
	AuthorizedKeysData    listOrString `yaml:"authorized_keys_data,omitempty"`
	TrustedUserCAKeys     listOrString `yaml:"trusted_user_ca_keys,omitempty"`
	TrustedUserCAKeysData listOrString `yaml:"trusted_user_ca_keys_data,omitempty"`
}

func (f yamlPipeFrom) SupportPublicKey() bool {
	return f.AuthorizedKeys.Any() || f.AuthorizedKeysData.Any() || f.TrustedUserCAKeys.Any() || f.TrustedUserCAKeysData.Any()
}

type yamlPipeTo struct {
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

type yamlPipe struct {
	From []yamlPipeFrom `yaml:"from,flow"`
	To   yamlPipeTo     `yaml:"to,flow"`
}

type skelpipeWrapper struct {
	plugin *plugin

	pipe *yamlPipe
}

func (s *skelpipeWrapper) From() []libplugin.SkelPipeFrom {
	var froms []libplugin.SkelPipeFrom
	for _, f := range s.pipe.From {

		w := &skelpipePasswordWrapper{
			plugin: s.plugin,
			from:   &f,
			to:     &s.pipe.To,
		}

		if f.SupportPublicKey() {
			froms = append(froms, &skelpipePublicKeyWrapper{
				skelpipePasswordWrapper: *w,
			})
		} else {
			froms = append(froms, w)
		}
	}
	return froms
}

type skelpipePasswordWrapper struct {
	plugin *plugin
	// conn   libplugin.ConnMetadata

	from *yamlPipeFrom
	to   *yamlPipeTo
}

type skelpipeToPasswordWrapper struct {
	plugin *plugin

	username string
	to       *yamlPipeTo
}

func (s *skelpipeToPasswordWrapper) User(conn libplugin.ConnMetadata) string {
	return s.username
}

func (s *skelpipeToPasswordWrapper) Host(conn libplugin.ConnMetadata) string {
	return s.to.Host
}

func (s *skelpipeToPasswordWrapper) IgnoreHostKey(conn libplugin.ConnMetadata) bool {
	return s.to.IgnoreHostkey
}

func (s *skelpipeToPasswordWrapper) KnownHosts(conn libplugin.ConnMetadata) ([]byte, error) {
	return s.plugin.loadFileOrDecodeMany(s.to.KnownHosts, s.to.KnownHostsData, map[string]string{
		"DOWNSTREAM_USER": conn.User(),
		"UPSTREAM_USER":   s.username,
	})
}

func (s *skelpipePasswordWrapper) Match(conn libplugin.ConnMetadata) (libplugin.SkelPipeTo, error) {
	user := conn.User()

	matched := s.from.Username == user
	targetuser := s.to.Username

	if targetuser == "" {
		targetuser = user
	}

	if s.from.UsernameRegexMatch {
		re, err := regexp.Compile(s.from.Username)
		if err != nil {
			return nil, err
		}

		matched = re.MatchString(user)

		if matched {
			targetuser = re.ReplaceAllString(user, s.to.Username)
		}
	}

	if matched {
		return &skelpipeToPasswordWrapper{
			plugin:   s.plugin,
			username: targetuser,
			to:       s.to,
		}, nil
	}

	return nil, nil
}

type skelpipePublicKeyWrapper struct {
	skelpipePasswordWrapper
}

func (s *skelpipePublicKeyWrapper) AuthorizedKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	return s.plugin.loadFileOrDecodeMany(s.from.AuthorizedKeys, s.from.AuthorizedKeysData, map[string]string{
		"DOWNSTREAM_USER": conn.User(),
	})
}

func (s *skelpipePublicKeyWrapper) TrustedUserCAKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	return s.plugin.loadFileOrDecodeMany(s.from.TrustedUserCAKeys, s.from.TrustedUserCAKeysData, map[string]string{
		"DOWNSTREAM_USER": conn.User(),
	})
}

func (s *skelpipeToPasswordWrapper) PrivateKey(conn libplugin.ConnMetadata) ([]byte, error) {
	return s.plugin.loadFileOrDecode(s.to.PrivateKey, s.to.PrivateKeyData, map[string]string{
		"DOWNSTREAM_USER": conn.User(),
		"UPSTREAM_USER":   s.username,
	})
}

type piperConfig struct {
	Version string     `yaml:"version"`
	Pipes   []yamlPipe `yaml:"pipes,flow"`
}

type plugin struct {
	File        string
	NoCheckPerm bool
}

func newYamlPlugin() *plugin {
	return &plugin{}
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

func (p *plugin) listPipe() ([]libplugin.SkelPipe, error) {
	config, err := p.loadConfig()
	if err != nil {
		return nil, err
	}

	var pipes []libplugin.SkelPipe
	for _, pipe := range config.Pipes {
		wrapper := &skelpipeWrapper{
			plugin: p,
			pipe:   &pipe,
		}
		pipes = append(pipes, wrapper)

	}

	return pipes, nil
}