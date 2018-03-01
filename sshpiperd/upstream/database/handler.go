package database

import (
	"net"

	"golang.org/x/crypto/ssh"
	"fmt"
)

func (p *plugin) findUpstream(conn ssh.ConnMetadata) (net.Conn, *ssh.AuthPipe, error) {

	db := p.db
	user := conn.User()

	d := downstream{}

	if err := db.Where(&downstream{Username: user}).First(&d).Error; err != nil{
		return nil, nil, err
	}

	fmt.Print(d)

	return nil, nil, nil
}
