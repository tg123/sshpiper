package mysql

import (
	"net"

	"golang.org/x/crypto/ssh"
)

func (p *plugin) findUpstream(conn ssh.ConnMetadata) (net.Conn, *ssh.AuthPipe, error) {

	db := p.db
	user := conn.User()

	d := Downstream{}

	db.Where(&Downstream{Username: user}).First(&d)



	return nil, nil,nil
}
