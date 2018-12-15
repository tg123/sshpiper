package database

import (
	"bytes"
	"net"

	"golang.org/x/crypto/ssh"
)

func (p *plugin) findUpstream(conn ssh.ConnMetadata) (net.Conn, *ssh.AuthPipe, error) {

	db := p.db
	user := conn.User()

	d := downstream{}

	if err := db.Set("gorm:auto_preload", true).Where(&downstream{Username: user}).First(&d).Error; err != nil {
		return nil, nil, err
	}

	addr := d.Upstream.Server.Address

	c, err := dial(addr)

	if err != nil {
		return nil, nil, err
	}

	pipe := ssh.AuthPipe{
		User: d.Upstream.Username,

		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {

			expectKey := key.Marshal()
			for _, k := range d.AuthorizedKeys {
				publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.Key.Data))

				if err != nil {
					logger.Printf("parse [keyid = %v] error :%v. skip to next key", k.Key.ID, err)
					continue
				}

				if bytes.Equal(publicKey.Marshal(), expectKey) {

					signer, err := ssh.ParsePrivateKey([]byte(d.Upstream.PrivateKey.Key.Data))

					if err != nil || signer == nil {
						break
					}

					return ssh.AuthPipeTypeMap, ssh.PublicKeys(signer), nil
				}
			}

			return ssh.AuthPipeTypeNone, nil, nil
		},

		UpstreamHostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	return c, &pipe, nil
}

func dial(addr string) (net.Conn, error) {

	if _, _, err := net.SplitHostPort(addr); err != nil && addr != "" {
		// test valid after concat :22
		if _, _, err := net.SplitHostPort(addr + ":22"); err == nil {
			addr += ":22"
		}
	}

	return net.Dial("tcp", addr)
}
