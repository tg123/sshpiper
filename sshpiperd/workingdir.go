// Copyright 2014, 2015 tgic<farmer1992@gmail.com>. All rights reserved.
// this file is governed by MIT-license
//
// https://github.com/tg123/sshpiper

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"

	"github.com/tg123/sshpiper/ssh"
)

type userFile string

var (
	UserAuthorizedKeysFile userFile = "authorized_keys"
	UserKeyFile            userFile = "id_rsa"
	UserUpstreamFile       userFile = "sshpiper_upstream"
)

func userSpecFile(user, file string) string {
	return fmt.Sprintf("%s/%s/%s", config.WorkingDir, user, file)
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

	if fi.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%v's perm is too open", filename)
	}

	return nil
}

func parseUpstreamFile(data string) (string, string) {

	var user string
	var line string

	r := bufio.NewReader(strings.NewReader(data))

	for {
		var err error
		line, err = r.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)

		if line != "" && line[0] != '#' {
			break
		}
	}

	t := strings.SplitN(line, "@", 2)

	if len(t) > 1 {
		user = t[0]
		line = t[1]
	}

	// test if ok
	if _, _, err := net.SplitHostPort(line); err != nil && line != "" {
		// test valid after concat :22
		if _, _, err := net.SplitHostPort(line + ":22"); err == nil {
			line += ":22"
		}
	}

	return line, user
}

func findUpstreamFromUserfile(conn ssh.ConnMetadata) (net.Conn, string, error) {
	user := conn.User()

	err := UserUpstreamFile.checkPerm(user)
	if err != nil {
		return nil, "", err
	}

	data, err := UserUpstreamFile.read(user)
	if err != nil {
		return nil, "", err
	}

	addr, mappedUser := parseUpstreamFile(string(data))

	if addr == "" {
		return nil, "", fmt.Errorf("empty addr")
	}

	logger.Printf("mapping user [%v] to [%v@%v]", user, mappedUser, addr)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, "", err
	}

	return c, mappedUser, nil
}

func mapPublicKeyFromUserfile(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.Signer, error) {
	user := conn.User()

	var err error
	defer func() { // print error when func exit
		if err != nil {
			logger.Printf("mapping private key error: %v, public key auth denied for [%v] from [%v]", err, user, conn.RemoteAddr())
		}
	}()

	err = UserAuthorizedKeysFile.checkPerm(user)
	if err != nil {
		return nil, err
	}

	keydata := key.Marshal()

	var rest []byte
	rest, err = UserAuthorizedKeysFile.read(user)
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
			err = UserKeyFile.checkPerm(user)
			if err != nil {
				return nil, err
			}

			var privateBytes []byte
			privateBytes, err = UserKeyFile.read(user)
			if err != nil {
				return nil, err
			}

			var private ssh.Signer
			private, err = ssh.ParsePrivateKey(privateBytes)
			if err != nil {
				return nil, err
			}

			// in log may see this twice, one is for query the other is real sign again
			logger.Printf("auth succ, using mapped private key [%v] for user [%v] from [%v]", UserKeyFile.realPath(user), user, conn.RemoteAddr())
			return private, nil
		}
	}

	logger.Printf("public key auth failed user [%v] from [%v]", conn.User(), conn.RemoteAddr())

	return nil, nil
}
