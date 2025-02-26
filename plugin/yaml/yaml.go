//go:build full || e2e

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
)

type yamlPipeFrom struct {
 	Username              string       `yaml:"username,omitempty"`
	Groupname	            string       `yaml:"groupname,omitempty"`
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

type piperConfig struct {
	Version string     `yaml:"version"`
	Pipes   []yamlPipe `yaml:"pipes,flow"`

	filename string
}

type plugin struct {
	FileGlobs   cli.StringSlice
	NoCheckPerm bool
}

func newYamlPlugin() *plugin {
	return &plugin{}
}

func (p *plugin) checkPerm(filename string) error {
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

func (p *plugin) loadConfig() ([]piperConfig, error) {
	var allconfig []piperConfig

	for _, fg := range p.FileGlobs.Value() {
		files, err := filepath.Glob(fg)
		if err != nil {
			return nil, err
		}

		for _, file := range files {

			if err := p.checkPerm(file); err != nil {
				return nil, err
			}

			configbyte, err := os.ReadFile(file)
			if err != nil {
				return nil, err
			}

			var config piperConfig

			err = yaml.Unmarshal(configbyte, &config)
			if err != nil {
				return nil, err
			}

			config.filename = file

			allconfig = append(allconfig, config)

		}
	}

	return allconfig, nil
}

func (p *piperConfig) loadFileOrDecode(file string, base64data string, vars map[string]string) ([]byte, error) {
	if file != "" {

		file = os.Expand(file, func(placeholderName string) string {
			v, ok := vars[placeholderName]
			if ok {
				return v
			}

			return os.Getenv(placeholderName)
		})

		if !filepath.IsAbs(file) {
			file = filepath.Join(filepath.Dir(p.filename), file)
		}

		return os.ReadFile(file)
	}

	if base64data != "" {
		return base64.StdEncoding.DecodeString(base64data)
	}

	return nil, nil
}

func (p *piperConfig) loadFileOrDecodeMany(files listOrString, base64data listOrString, vars map[string]string) ([]byte, error) {
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
