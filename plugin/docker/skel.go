//go:build full || e2e

package main

import (
	"encoding/base64"

	"github.com/tg123/sshpiper/libplugin"
)

type skelpipeWrapper struct {
	plugin *plugin

	pipe *pipe
}

type skelpipePasswordWrapper struct {
	skelpipeWrapper
}

type skelpipeToWrapper struct {
	skelpipeWrapper

	username string
}

func (s *skelpipeWrapper) From() []libplugin.SkelPipeFrom {

	w := &skelpipePasswordWrapper{
		skelpipeWrapper: *s,
	}

	if s.pipe.PrivateKey != "" || s.pipe.AuthorizedKeys != "" {
		return []libplugin.SkelPipeFrom{&skelpipePublicKeyWrapper{
			skelpipePasswordWrapper: *w,
		}}
	}

	return []libplugin.SkelPipeFrom{w}

}

func (s *skelpipeToWrapper) User(conn libplugin.ConnMetadata) string {
	return s.username
}

func (s *skelpipeToWrapper) Host(conn libplugin.ConnMetadata) string {
	return s.pipe.Host
}

func (s *skelpipeToWrapper) IgnoreHostKey(conn libplugin.ConnMetadata) bool {
	return true // TODO support this
}

func (s *skelpipeToWrapper) KnownHosts(conn libplugin.ConnMetadata) ([]byte, error) {
	return nil, nil // TODO support this
}

func (s *skelpipePasswordWrapper) MatchConn(conn libplugin.ConnMetadata) (libplugin.SkelPipeTo, error) {
	user := conn.User()

	matched := s.pipe.ClientUsername == user || s.pipe.ClientUsername == ""
	targetuser := s.pipe.ClientUsername

	if targetuser == "" {
		targetuser = user
	}

	if matched {
		return &skelpipeToWrapper{
			skelpipeWrapper: s.skelpipeWrapper,
			username:        targetuser,
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
	return base64.StdEncoding.DecodeString(s.pipe.AuthorizedKeys)
}

func (s *skelpipePublicKeyWrapper) TrustedUserCAKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	return nil, nil // TODO support this
}

func (s *skelpipeToWrapper) PrivateKey(conn libplugin.ConnMetadata) ([]byte, []byte, error) {
	k, err := base64.StdEncoding.DecodeString(s.pipe.PrivateKey)
	if err != nil {
		return nil, nil, err
	}

	return k, nil, nil
}

func (s *skelpipeToWrapper) OverridePassword(conn libplugin.ConnMetadata) ([]byte, error) {
	return nil, nil
}

func (p *plugin) listPipe() ([]libplugin.SkelPipe, error) {
	dpipes, err := p.list()
	if err != nil {
		return nil, err
	}

	var pipes []libplugin.SkelPipe
	for _, pipe := range dpipes {
		wrapper := &skelpipeWrapper{
			plugin: p,
			pipe:   &pipe,
		}
		pipes = append(pipes, wrapper)

	}

	return pipes, nil
}
