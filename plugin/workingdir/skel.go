package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
)

type workdingdirFactory struct {
	root             string
	allowBadUsername bool
	noPasswordAuth   bool
	noCheckPerm      bool
	strictHostKey    bool
	recursiveSearch  bool
}

type skelpipeWrapper struct {
	dir *workingdir

	host     string
	username string
}

type skelpipeFromWrapper struct {
	skelpipeWrapper
}

type skelpipePasswordWrapper struct {
	skelpipeFromWrapper
}

type skelpipePublicKeyWrapper struct {
	skelpipeFromWrapper
}

type skelpipeToWrapper struct {
	skelpipeWrapper
}

type skelpipeToPasswordWrapper struct {
	skelpipeToWrapper
}

type skelpipeToPrivateKeyWrapper struct {
	skelpipeToWrapper
}

func (s *skelpipeWrapper) From() []libplugin.SkelPipeFrom {

	w := skelpipeFromWrapper{
		skelpipeWrapper: *s,
	}

	if s.dir.Exists(userAuthorizedKeysFile) && s.dir.Exists(userKeyFile) {
		return []libplugin.SkelPipeFrom{&skelpipePublicKeyWrapper{
			skelpipeFromWrapper: w,
		}}
	} else {
		return []libplugin.SkelPipeFrom{&skelpipePasswordWrapper{
			skelpipeFromWrapper: w,
		}}
	}
}

func (s *skelpipeToWrapper) User(conn libplugin.ConnMetadata) string {
	return s.username
}

func (s *skelpipeToWrapper) Host(conn libplugin.ConnMetadata) string {
	return s.host
}

func (s *skelpipeToWrapper) IgnoreHostKey(conn libplugin.ConnMetadata) bool {
	return !s.dir.Strict
}

func (s *skelpipeToWrapper) KnownHosts(conn libplugin.ConnMetadata) ([]byte, error) {
	return s.dir.Readfile(userKnownHosts)
}

func (s *skelpipeFromWrapper) MatchConn(conn libplugin.ConnMetadata) (libplugin.SkelPipeTo, error) {

	if s.dir.Exists(userKeyFile) {
		return &skelpipeToPrivateKeyWrapper{
			skelpipeToWrapper: skelpipeToWrapper(*s),
		}, nil
	}

	return &skelpipeToPasswordWrapper{
		skelpipeToWrapper: skelpipeToWrapper(*s),
	}, nil
}

func (s *skelpipePasswordWrapper) TestPassword(conn libplugin.ConnMetadata, password []byte) (bool, error) {
	return true, nil // TODO support later
}

func (s *skelpipePublicKeyWrapper) AuthorizedKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	return s.dir.Readfile(userAuthorizedKeysFile)
}

func (s *skelpipePublicKeyWrapper) TrustedUserCAKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	return nil, nil // TODO support this
}

func (s *skelpipeToPrivateKeyWrapper) PrivateKey(conn libplugin.ConnMetadata) ([]byte, []byte, error) {
	k, err := s.dir.Readfile(userKeyFile)
	if err != nil {
		return nil, nil, err
	}

	return k, nil, nil
}

func (s *skelpipeToPasswordWrapper) OverridePassword(conn libplugin.ConnMetadata) ([]byte, error) {
	return nil, nil
}

func (wf *workdingdirFactory) listPipe(conn libplugin.ConnMetadata) ([]libplugin.SkelPipe, error) {

	user := conn.User()

	if !wf.allowBadUsername {
		if !isUsernameSecure(user) {
			return nil, fmt.Errorf("bad username: %s", user)
		}
	}

	var pipes []libplugin.SkelPipe
	userdir := path.Join(wf.root, conn.User())

	_ = filepath.Walk(userdir, func(path string, info os.FileInfo, err error) (stop error) {

		log.Infof("search upstreams in path: %v", path)
		if err != nil {
			log.Infof("error walking path: %v", err)
			return
		}

		if !info.IsDir() {
			return
		}

		if !wf.recursiveSearch {
			stop = fmt.Errorf("stop")
		}

		w := &workingdir{
			Path:        path,
			NoCheckPerm: wf.noCheckPerm,
			Strict:      wf.strictHostKey,
		}

		data, err := w.Readfile(userUpstreamFile)
		if err != nil {
			log.Infof("error reading upstream file: %v in %v", err, w.Path)
			return
		}

		host, user, err := parseUpstreamFile(string(data))
		if err != nil {
			log.Infof("ignore upstream folder %v due to: %v", w.Path, err)
			return
		}

		pipes = append(pipes, &skelpipeWrapper{
			dir:      w,
			host:     host,
			username: user,
		})

		return
	})

	return pipes, nil
}
