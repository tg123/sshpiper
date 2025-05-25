//go:build full || e2e

package main

import (
	"errors"
	"os/user"
	"regexp"
	"slices"

	log "github.com/sirupsen/logrus"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/libplugin/skel"
)

type skelpipeWrapper struct {
	pipe   *yamlPipe
	config *piperConfig
}
type skelpipeFromWrapper struct {
	config *piperConfig

	from *yamlPipeFrom
	to   *yamlPipeTo
}
type skelpipePasswordWrapper struct {
	skelpipeFromWrapper
}

type skelpipePublicKeyWrapper struct {
	skelpipeFromWrapper
}

type skelpipeToWrapper struct {
	config *piperConfig

	username string
	to       *yamlPipeTo
}

type skelpipeToPasswordWrapper struct {
	skelpipeToWrapper
}

type skelpipeToPrivateKeyWrapper struct {
	skelpipeToWrapper
}

func (s *skelpipeWrapper) From() []skel.SkelPipeFrom {
	var froms []skel.SkelPipeFrom
	for _, f := range s.pipe.From {

		w := &skelpipeFromWrapper{
			config: s.config,
			from:   &f,
			to:     &s.pipe.To,
		}

		if f.SupportPublicKey() {
			froms = append(froms, &skelpipePublicKeyWrapper{
				skelpipeFromWrapper: *w,
			})
		} else {
			froms = append(froms, &skelpipePasswordWrapper{
				skelpipeFromWrapper: *w,
			})
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
	return s.config.loadFileOrDecodeMany(s.to.KnownHosts, s.to.KnownHostsData, map[string]string{
		"DOWNSTREAM_USER": conn.User(),
		"UPSTREAM_USER":   s.username,
	})
}

func (s *skelpipeFromWrapper) MatchConn(conn libplugin.ConnMetadata) (skel.SkelPipeTo, error) {
	username := conn.User()

	targetuser := s.to.Username

	var matched bool
	if s.from.Username != "" {
		matched = s.from.Username == username
		if s.from.UsernameRegexMatch {
			re, err := regexp.Compile(s.from.Username)
			if err != nil {
				return nil, err
			}

			matched = re.MatchString(username)

			if matched {
				targetuser = re.ReplaceAllString(username, s.to.Username)
			}
		}
	} else if s.from.Groupname != "" {
		// check user is known to the system before grouplookup
		usr, err := user.Lookup(username)
		if err != nil {
			var unknownUser user.UnknownUserError
			if errors.As(err, &unknownUser) {
				return nil, nil
			}
			log.Errorf("[ERROR] Matchconn(): Failure looking up user %q: %T - %v", username, err, err)
			return nil, err
		}
		userGroups, err := getUserGroups(usr)
		if err != nil {
			return nil, err
		}
		fromPipeGroup := s.from.Groupname
		matched = slices.Contains(userGroups, fromPipeGroup)
	}

	if targetuser == "" {
		targetuser = username
	}

	if matched {

		if s.to.PrivateKey != "" || s.to.PrivateKeyData != "" {
			return &skelpipeToPrivateKeyWrapper{
				skelpipeToWrapper: skelpipeToWrapper{
					config:   s.config,
					username: targetuser,
					to:       s.to,
				},
			}, nil
		}

		return &skelpipeToPasswordWrapper{
			skelpipeToWrapper: skelpipeToWrapper{
				config:   s.config,
				username: targetuser,
				to:       s.to,
			},
		}, nil
	}

	return nil, nil
}

func (s *skelpipePasswordWrapper) TestPassword(conn libplugin.ConnMetadata, password []byte) (bool, error) {
	return true, nil // yaml do not test input password
}

func (s *skelpipePublicKeyWrapper) AuthorizedKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	return s.config.loadFileOrDecodeMany(s.from.AuthorizedKeys, s.from.AuthorizedKeysData, map[string]string{
		"DOWNSTREAM_USER": conn.User(),
	})
}

func (s *skelpipePublicKeyWrapper) TrustedUserCAKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	return s.config.loadFileOrDecodeMany(s.from.TrustedUserCAKeys, s.from.TrustedUserCAKeysData, map[string]string{
		"DOWNSTREAM_USER": conn.User(),
	})
}

func (s *skelpipeToPrivateKeyWrapper) PrivateKey(conn libplugin.ConnMetadata) ([]byte, []byte, error) {
	p, err := s.config.loadFileOrDecode(s.to.PrivateKey, s.to.PrivateKeyData, map[string]string{
		"DOWNSTREAM_USER": conn.User(),
		"UPSTREAM_USER":   s.username,
	})
	if err != nil {
		return nil, nil, err
	}

	return p, nil, nil
}

func (s *skelpipeToPasswordWrapper) OverridePassword(conn libplugin.ConnMetadata) ([]byte, error) {
	return nil, nil
}

func (p *plugin) listPipe(_ libplugin.ConnMetadata) ([]skel.SkelPipe, error) {
	configs, err := p.loadConfig()
	if err != nil {
		return nil, err
	}

	var pipes []skel.SkelPipe
	for _, config := range configs {
		for _, pipe := range config.Pipes {
			wrapper := &skelpipeWrapper{
				config: &config,
				pipe:   &pipe,
			}
			pipes = append(pipes, wrapper)

		}
	}

	return pipes, nil
}

func getUserGroups(usr *user.User) ([]string, error) {
	groupIds, err := usr.GroupIds()
	if err != nil {
		log.Errorf("[ERROR] getUserGroups(): Failure retrieving group IDs for %q: %T - %v", usr.Username, err, err)
		return nil, err
	}

	var groups []string
	for _, groupId := range groupIds {
		grp, err := user.LookupGroupId(groupId)
		if err != nil {
			log.Errorf("[ERROR] getUserGroups(): Failure retrieving group name for %q: %T - %v", usr.Username, err, err)
			return nil, err
		}
		groups = append(groups, grp.Name)
	}

	return groups, nil
}
