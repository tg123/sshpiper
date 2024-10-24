//go:build full || e2e

package main

import (
	"regexp"

	"github.com/tg123/sshpiper/libplugin"
)

type skelpipeWrapper struct {
	plugin *plugin

	pipe *yamlPipe
}

type skelpipePasswordWrapper struct {
	plugin *plugin

	from *yamlPipeFrom
	to   *yamlPipeTo
}

type skelpipeToWrapper struct {
	plugin *plugin

	username string
	to       *yamlPipeTo
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

func (s *skelpipeToWrapper) User(conn libplugin.ConnMetadata) string {
	return s.username
}

func (s *skelpipeToWrapper) Host(conn libplugin.ConnMetadata) string {
	return s.to.Host
}

func (s *skelpipeToWrapper) IgnoreHostKey(conn libplugin.ConnMetadata) bool {
	return s.to.IgnoreHostkey
}

func (s *skelpipeToWrapper) KnownHosts(conn libplugin.ConnMetadata) ([]byte, error) {
	return s.plugin.loadFileOrDecodeMany(s.to.KnownHosts, s.to.KnownHostsData, map[string]string{
		"DOWNSTREAM_USER": conn.User(),
		"UPSTREAM_USER":   s.username,
	})
}

func (s *skelpipePasswordWrapper) MatchConn(conn libplugin.ConnMetadata) (libplugin.SkelPipeTo, error) {
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
		return &skelpipeToWrapper{
			plugin:   s.plugin,
			username: targetuser,
			to:       s.to,
		}, nil
	}

	return nil, nil
}

func (s *skelpipePasswordWrapper) TestPassword(conn libplugin.ConnMetadata, password []byte) (bool, error) {
	return true, nil // yaml do not test input password
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

func (s *skelpipeToWrapper) PrivateKey(conn libplugin.ConnMetadata) ([]byte, []byte, error) {
	p, err := s.plugin.loadFileOrDecode(s.to.PrivateKey, s.to.PrivateKeyData, map[string]string{
		"DOWNSTREAM_USER": conn.User(),
		"UPSTREAM_USER":   s.username,
	})

	if err != nil {
		return nil, nil, err
	}

	return p, nil, nil
}

func (s *skelpipeToWrapper) OverridePassword(conn libplugin.ConnMetadata) ([]byte, error) {
	return nil, nil
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
