// Copyright 2014, 2015 tgic<farmer1992@gmail.com>. All rights reserved.
// this file is governed by MIT-license
//
// https://github.com/tg123/sshpiper

package workingdir

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/tg123/sshpiper/sshpiperd/upstream"
	"golang.org/x/crypto/ssh/knownhosts"
	"io/ioutil"
	"net"
	"os"
	"path"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

type userFile string

var (
	userAuthorizedKeysFile userFile = "authorized_keys"
	userKeyFile            userFile = "id_rsa"
	userUpstreamFile       userFile = "sshpiper_upstream"
	userKnownHosts         userFile = "known_hosts"

	usernameRule *regexp.Regexp
)

func init() {
	// Base username validation on Debians default: https://sources.debian.net/src/adduser/3.113%2Bnmu3/adduser.conf/#L85
	// -> NAME_REGEX="^[a-z][-a-z0-9_]*\$"
	// The length is limited to 32 characters. See man 8 useradd: https://linux.die.net/man/8/useradd
	usernameRule, _ = regexp.Compile("^[a-z_][-a-z0-9_]{0,31}$")
}

func userSpecFile(user, file string) string {
	return path.Join(config.WorkingDir, user, file)
}

func (file userFile) read(user string) ([]byte, error) {
	return ioutil.ReadFile(userSpecFile(user, string(file)))
}

func (file userFile) realPath(user string) string {
	return userSpecFile(user, string(file))
}

// return error if other and group have access right
func (file userFile) checkPerm(user string) error {
	filename := userSpecFile(user, string(file))
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}

	if config.NoCheckPerm {
		return nil
	}

	if fi.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%v's perm is too open", filename)
	}

	return nil
}

// return false if username is not a valid unix user name
// this is for security reason
func checkUsername(user string) bool {
	if config.AllowBadUsername {
		return true
	}

	return usernameRule.MatchString(user)
}

func parseUpstreamFile(data string) (host string, port int, user string, err error) {
	r := bufio.NewReader(strings.NewReader(data))
	for {
		host, err = r.ReadString('\n')
		if err != nil {
			break
		}

		host = strings.TrimSpace(host)

		if host != "" && host[0] != '#' {
			break
		}
	}

	t := strings.SplitN(host, "@", 2)

	if len(t) > 1 {
		user = t[0]
		host = t[1]
	}

	host, port, err = upstream.SplitHostPortForSSH(host)
	return
}

func findUpstreamFromUserfile(conn ssh.ConnMetadata, challengeContext ssh.AdditionalChallengeContext) (net.Conn, *ssh.AuthPipe, error) {
	user := conn.User()

	if !checkUsername(user) {
		return nil, nil, fmt.Errorf("downstream is not using a valid username")
	}

	err := userUpstreamFile.checkPerm(user)

	if os.IsNotExist(err) && len(config.FallbackUsername) > 0 {
		user = config.FallbackUsername
	} else if err != nil {
		return nil, nil, err
	}

	data, err := userUpstreamFile.read(user)
	if err != nil {
		return nil, nil, err
	}

	host, port, mappedUser, err := parseUpstreamFile(string(data))
	if err != nil {
		return nil, nil, err
	}
	addr := fmt.Sprintf("%v:%v", host, port)

	logger.Printf("mapping user [%v] to [%v@%v]", user, mappedUser, addr)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, nil, err
	}

	hostKeyCallback := ssh.InsecureIgnoreHostKey()

	if config.StrictHostKey {
		hostKeyCallback, err = knownhosts.New(userKnownHosts.realPath(user))

		if err != nil {
			return nil, nil, err
		}
	}

	return c, &ssh.AuthPipe{
		User: mappedUser,

		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {
			signer, err := mapPublicKeyFromUserfile(conn, key)

			if err != nil || signer == nil {
				// try one
				return ssh.AuthPipeTypeNone, nil, nil
			}

			return ssh.AuthPipeTypeMap, ssh.PublicKeys(signer), nil
		},

		UpstreamHostKeyCallback: hostKeyCallback,
	}, nil
}

func mapPublicKeyFromUserfile(conn ssh.ConnMetadata, key ssh.PublicKey) (signer ssh.Signer, err error) {
	user := conn.User()

	if !checkUsername(user) {
		return nil, fmt.Errorf("downstream is not using a valid username")
	}

	defer func() { // print error when func exit
		if err != nil {
			logger.Printf("mapping private key error: %v, public key auth denied for [%v] from [%v]", err, user, conn.RemoteAddr())
		}
	}()

	err = userAuthorizedKeysFile.checkPerm(user)

	if os.IsNotExist(err) && len(config.FallbackUsername) > 0 {
		err = nil
		user = config.FallbackUsername
	} else if err != nil {
		return nil, err
	}

	keydata := key.Marshal()

	var rest []byte
	rest, err = userAuthorizedKeysFile.read(user)
	if err != nil {
		return nil, err
	}

	var authedPubkey ssh.PublicKey

	for len(rest) > 0 {
		authedPubkey, _, _, rest, err = ssh.ParseAuthorizedKey(rest)

		if err != nil {
			return nil, err
		}

		if bytes.Equal(authedPubkey.Marshal(), keydata) {
			err = userKeyFile.checkPerm(user)
			if err != nil {
				return nil, err
			}

			var privateBytes []byte
			privateBytes, err = userKeyFile.read(user)
			if err != nil {
				return nil, err
			}

			var private ssh.Signer
			private, err = ssh.ParsePrivateKey(privateBytes)
			if err != nil {
				return nil, err
			}

			// in log may see this twice, one is for query the other is real sign again
			logger.Printf("auth succ, using mapped private key [%v] for user [%v] from [%v]", userKeyFile.realPath(user), user, conn.RemoteAddr())
			return private, nil
		}
	}

	logger.Printf("public key auth failed user [%v] from [%v]", conn.User(), conn.RemoteAddr())

	return nil, nil
}
