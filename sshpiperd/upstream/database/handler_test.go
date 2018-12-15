package database

import (
	"io"
	"testing"
	"log"
	"os"
	"net"
	"github.com/gokyle/sshkey"

	upstreamprovider "github.com/tg123/sshpiper/sshpiperd/upstream"
	"github.com/jinzhu/gorm"
)

func generateKeyPair() (string, string, error) {
	priv, err := sshkey.GenerateKey(sshkey.KEY_RSA, 2048)
	if err != nil {
		return "", "", err
	}

	privb, err := sshkey.MarshalPrivate(priv, "")
	if err != nil {
		return "", "", err
	}

	pub := sshkey.NewPublic(priv, "")

	return string(sshkey.MarshalPublic(pub)), string(privb), nil

}

func newTestPlugin(t *testing.T) (*plugin) {
	p := upstreamprovider.Get("sqlite").(*sqliteplugin)

	p.Config.File = "file::memory:?mode=memory&cache=shared"

	err := p.Init(log.New(os.Stdout, "", 0))
	if err != nil {
		t.Fatal(err)
	}

	return &p.plugin
}

type testconn struct {
	user string
}

func (c testconn) User() string {
	return c.user
}

func (testconn) SessionID() []byte {
	return nil
}

func (testconn) ClientVersion() []byte {
	return nil
}

func (testconn) ServerVersion() []byte {
	return nil
}

func (testconn) RemoteAddr() net.Addr {
	return nil
}

func (testconn) LocalAddr() net.Addr {
	return nil
}

func createEntry(t *testing.T, db *gorm.DB, downUser, upUser, serverAddr string, serverKey bool) {

	pub, priv, err := generateKeyPair()

	if err != nil {
		t.Fatal(err)
	}

	db.Create(&downstream{
		Username: downUser,
		AuthorizedKeys: []authorizedKey{
			{
				Key: keydata{
					Data: pub,
					Type: "rsa",
				},
			},
		},
		Upstream: upstream{
			Username:    upUser,
			AuthMapType: authMapTypePrivateKey,
			PrivateKey: privateKey{
				Key: keydata{
					Data: priv,
					Type: "rsa",
				},
			},
			Server: server{
				Address:       serverAddr,
				IgnoreHostKey: serverKey,
				HostKey: hostKey{
					Key: keydata{
						Data: pub,

						Type: "rsa",
					},
				},
			},
		},
	})
}

func TestFindUpstream(t *testing.T) {

	p := newTestPlugin(t)
	defer p.db.Close()
	db := p.db

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cant create fake server: %v", err)
	}
	defer listener.Close()

	go func() {
		c, err := listener.Accept()
		if err != nil {
			t.Errorf("fake server error %v", err)
			return
		}
		io.Copy(c, c)
		c.Close()
	}()

	h := p.GetHandler()

	createEntry(t, db, "abc", "efg", listener.Addr().String(), false)

	_, _, err = h(testconn{"abc"})
	if err != nil {
		t.Fatal(err)
	}

}
