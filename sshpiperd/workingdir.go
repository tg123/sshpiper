// Copyright 2014, 2015 tgic<farmer1992@gmail.com>. All rights reserved.
// this file is governed by MIT-license
//
// https://github.com/tg123/sshpiper

package main

import (
	"bytes"
	"fmt"
	"github.com/tg123/sshpiper/ssh"
	"io/ioutil"
	"net"
	"os"
	"strings"
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

func findUpstreamFromUserfile(conn ssh.ConnMetadata) (net.Conn, error) {
	user := conn.User()

	err := UserUpstreamFile.checkPerm(user)
	if err != nil {
		return nil, err
	}

	addr, err := UserUpstreamFile.read(user)
	if err != nil {
		return nil, err
	}

	saddr := strings.TrimSpace(string(addr))

	logger.Printf("mapping user [%s] to [%s]", user, saddr)

	c, err := net.Dial("tcp", saddr)
	if err != nil {
		return nil, err
	}

	return c, nil
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
