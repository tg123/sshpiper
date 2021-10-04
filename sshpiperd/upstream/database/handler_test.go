package database

import (
	"log"
	"net"
	"os"
	"testing"

	"github.com/gokyle/sshkey"
	"golang.org/x/crypto/ssh"

	"github.com/jinzhu/gorm"
	upstreamprovider "github.com/tg123/sshpiper/sshpiperd/upstream"
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

func newTestPlugin(t *testing.T) *plugin {
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

func createEntry(t *testing.T, db *gorm.DB, downUser, upUser, serverAddr string, ignoreServerKey bool) (string, string) {

	pub, priv, err := generateKeyPair()

	if err != nil {
		t.Fatal(err)
	}

	err = db.Create(&downstream{
		Username:    downUser,
		AuthMapType: authMapTypeAny,
		AuthorizedKeys: keydata{
			Data: pub,
			Type: "rsa",
		},
		Upstream: upstream{
			Username:    upUser,
			AuthMapType: authMapTypePrivateKey,
			PrivateKey: keydata{
				Data: priv,
				Type: "rsa",
			},
			Server: server{
				Address:       serverAddr,
				IgnoreHostKey: ignoreServerKey,
				HostKey: keydata{
					Data: pub,
					Type: "rsa",
				},
			},
		},
	}).Error

	if err != nil {
		t.Fatal(err)
	}

	return pub, priv
}

func TestFindUpstream(t *testing.T) {

	p := newTestPlugin(t)
	defer p.db.Close()
	db := p.db
	h := p.GetHandler()

	listener, err := createListener(t)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	createEntry(t, db, "finddown0", "findup0", listener.Addr().String(), true)
	createEntry(t, db, "finddown1", "findup1", listener.Addr().String(), true)
	createEntry(t, db, "finddown2", "findup2", listener.Addr().String(), true)

	_, auth, err := h(testconn{"finddown0"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if auth.User != "findup0" {
		t.Error("auth pipe user name is not correct")
	}

	db.Delete(&config{Entry: fallbackUserEntry})
	_, _, err = h(testconn{"not_exists"}, nil)
	if err == nil {
		t.Error("should not found any user")
	}

	db.NewRecord(&config{Entry: fallbackUserEntry, Value: "findup0"})
	_, auth, err = h(testconn{"finddown0"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if auth.User != "findup0" {
		t.Error("auth pipe user name is not correct (fallback)")
	}
}

func TestPublicKeyCallback(t *testing.T) {

	p := newTestPlugin(t)
	defer p.db.Close()
	db := p.db
	h := p.GetHandler()

	listener, err := createListener(t)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	pub, _ := createEntry(t, db, "pkdown", "pkdown", listener.Addr().String(), true)

	_, auth, err := h(testconn{"pkdown"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub))
	if err != nil {
		t.Fatal(err)
	}

	authType, method, err := auth.PublicKeyCallback(nil, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	if authType != ssh.AuthPipeTypeMap {
		t.Error("auth type map should be AuthPipeTypeMap")
	}

	if method == nil {
		t.Error("auth method is missing")
	}
}

func createListener(t *testing.T) (net.Listener, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cant create fake server: %v", err)
	}
	// go listener.Accept()
	return listener, err
}
