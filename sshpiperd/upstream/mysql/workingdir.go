package mysql

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/tg123/sshpiper/sshpiperd/upstream/mysql/crud"
)

type mysqlWorkingDir struct {
	ConnectDB func() (*sql.DB, error)
}

func connectServer(db *sql.DB, sid int64) (net.Conn, error) {

	o := crud.NewServer(db)

	s, err := o.GetFirstById(sid)
	if err != nil {
		return nil, err
	}

	if s == nil {
		return nil, fmt.Errorf("server [%v] not found", sid)
	}

	addr := s.Address
	// test if ok
	if _, _, err := net.SplitHostPort(addr); err != nil && addr != "" {
		// test valid after concat :22
		if _, _, err := net.SplitHostPort(addr + ":22"); err == nil {
			addr += ":22"
		}
	}

	return net.Dial("tcp", addr)
}
func (w *mysqlWorkingDir) connectUpstream(db *sql.DB, uid int64, defuser string) (net.Conn, *ssh.SSHPiperAuthPipe, error) {

	o := crud.NewUpstream(db)

	u, err := o.GetFirstById(uid)
	if err != nil {
		return nil, nil, err
	}

	if u == nil {
		return nil, nil, fmt.Errorf("upstream [%v] not found", uid)
	}

	c, err := connectServer(db, u.ServerId)
	if err != nil {
		return nil, nil, err
	}

	user := defuser

	if u.Username != "" {
		user = u.Username
	}

	logger.Printf("connecting upstream id [%v] addr [%v]@[%v] ", uid, user, c.RemoteAddr())
	return c, &ssh.SSHPiperAuthPipe{
		User: user,

		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {
			signer, err := w.MapPublicKey(conn, key)

			if err != nil || signer == nil {
				// try one
				return ssh.AuthPipeTypeNone, nil, nil
			}

			return ssh.AuthPipeTypeMap, ssh.PublicKeys(signer), nil
		},

		UpstreamHostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO should support by config
	}, nil
}

func findPKId(db *sql.DB, key ssh.PublicKey) (int64, error) {
	kstr := base64.StdEncoding.EncodeToString(key.Marshal())

	opk := crud.NewPublicKeys(db)
	k, err := opk.GetFirstByData(kstr)
	if err != nil {
		return -1, err
	}

	if k != nil {
		return k.Id, nil
	}

	return -1, nil
}

//func findByPublicKey(db *sql.DB, downkey ssh.PublicKey) (int64, error) {
//	kid, err := findPKId(db, downkey)
//	if err != nil {
//		return -1, err
//	}
//
//	if kid > 0 {
//		opum := crud.NewPubkeyUpstreamMap(db)
//		u, err := opum.GetFirstByPubkeyId(kid)
//		if err != nil {
//			return -1, err
//		}
//
//		if u != nil {
//			return u.UpstreamId, nil
//		}
//	}
//
//	return -1, nil
//}

func findByUsername(db *sql.DB, username string) (int64, error) {
	ouum := crud.NewUserUpstreamMap(db)
	u, err := ouum.GetFirstByUsername(username)
	if err != nil {
		return -1, err
	}

	if u != nil {
		return u.UpstreamId, nil
	}

	return -1, nil
}

//func (w *mysqlWorkingDir) FindUpstream(conn ssh.ConnMetadata, downkey ssh.PublicKey) (net.Conn, *ssh.SSHPiperAuthPipe, error) {
func (w *mysqlWorkingDir) FindUpstream(conn ssh.ConnMetadata) (net.Conn, *ssh.SSHPiperAuthPipe, error) {

	db, err := w.ConnectDB()
	defer db.Close()
	if err != nil {
		return nil, nil, err
	}

	user := conn.User()

	//uid, err := findByPublicKey(db, downkey)

	//if err != nil {
	//	return nil, nil, err
	//}

	//// found
	//if uid > 0 {
	//	logger.Printf("upstream id [%v] found for [%v] by public key", uid, conn.RemoteAddr())
	//	return w.connectUpstream(db, uid, user)
	//}

	uid, err := findByUsername(db, user)

	if err != nil {
		return nil, nil, err
	}

	// found
	if uid > 0 {
		logger.Printf("upstream id [%v] found for [%v] by username", uid, conn.RemoteAddr())
		return w.connectUpstream(db, uid, user)
	}

	return nil, nil, fmt.Errorf("no upstream found")
}

func (w *mysqlWorkingDir) MapPublicKey(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.Signer, error) {
	db, err := w.ConnectDB()
	defer db.Close()
	if err != nil {
		return nil, err
	}

	kid, err := findPKId(db, key)
	if err != nil {
		return nil, err
	}

	if kid < 0 {
		logger.Printf("no sign again key mapping found for [%v]", conn.RemoteAddr())
		return nil, nil
	}

	oppm := crud.NewPubkeyPrikeyMap(db)

	m, err := oppm.GetFirstByPubkeyId(kid)
	if err != nil {
		return nil, err
	}

	if m != nil {
		op := crud.NewPrivateKeys(db)
		p, err := op.GetFirstById(m.PrivateKeyId)
		if err != nil {
			return nil, err
		}

		logger.Printf("mapping to public key [%v] to private key [%v] for [%v]", kid, p.Id, conn.RemoteAddr())

		k, err := ssh.ParsePrivateKey([]byte(p.Data))

		if err != nil {
			logger.Printf("failed to load private key for [%v]: [%v]", conn.RemoteAddr(), err)
		}

		return k, err
	}

	logger.Printf("no sign again key mapping found for [%v]", conn.RemoteAddr())
	return nil, nil
}
