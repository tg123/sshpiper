package database

import (
	"bytes"
	"github.com/jinzhu/gorm"
	"net"

	"golang.org/x/crypto/ssh"

	upstreamprovider "github.com/tg123/sshpiper/sshpiperd/upstream"
)

func (p *plugin) findUpstream(conn ssh.ConnMetadata, challengeContext ssh.AdditionalChallengeContext) (net.Conn, *ssh.AuthPipe, error) {

	user := conn.User()
	d, err := lookupDownstreamWithFallback(p.db, user)

	if err != nil {
		return nil, nil, err
	}

	addr := d.Upstream.Server.Address
	upuser := d.Upstream.Username

	if upuser == "" {
		upuser = d.Username
	}

	logger.Printf("mapping user [%v] to [%v@%v]", user, upuser, addr)

	c, err := upstreamprovider.DialForSSH(addr)

	if err != nil {
		return nil, nil, err
	}

	hostKeyCallback := ssh.InsecureIgnoreHostKey()

	if !d.Upstream.Server.IgnoreHostKey {

		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(d.Upstream.Server.HostKey.Key.Data))
		if err != nil {
			return nil, nil, err
		}

		hostKeyCallback = ssh.FixedHostKey(key)
	}

	pipe := ssh.AuthPipe{
		User: upuser,

		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (ssh.AuthPipeType, ssh.AuthMethod, error) {

			expectKey := key.Marshal()
			for _, k := range d.AuthorizedKeys {
				publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.Key.Data))

				if err != nil {
					logger.Printf("parse [keyid = %v] error :%v. skip to next key", k.Key.ID, err)
					continue
				}

				if bytes.Equal(publicKey.Marshal(), expectKey) {

					kinterf, err := ssh.ParseRawPrivateKey([]byte(d.Upstream.PrivateKey.Key.Data))
					if err != nil {
						break
					}

					signer, err := ssh.NewSignerFromKey(kinterf)
					if err != nil || signer == nil {
						break
					}

					return ssh.AuthPipeTypeMap, ssh.PublicKeys(signer), nil
				}
			}

			return ssh.AuthPipeTypeNone, nil, nil
		},

		UpstreamHostKeyCallback: hostKeyCallback,
	}
	return c, &pipe, nil
}

func lookupDownstreamWithFallback(db *gorm.DB, user string) (*downstream, error) {
	d, err := lookupDownstream(db, user)

	if gorm.IsRecordNotFoundError(err) {
		fallback, _ := lookupConfigValue(db, fallbackUserEntry)

		if len(fallback) > 0 {
			return lookupDownstream(db, fallback)
		}
	}

	return d, err
}

func lookupDownstream(db *gorm.DB, user string) (*downstream, error) {
	d := downstream{}

	if err := db.Set("gorm:auto_preload", true).Where(&downstream{Username: user}).First(&d).Error; err != nil {

		return nil, err
	}

	return &d, nil
}

func lookupConfigValue(db *gorm.DB, entry string) (string, error) {
	c := config{}
	if err := db.Where(&config{Entry: entry}).First(&c).Error; err != nil {
		return "", err
	}

	return c.Value, nil
}
