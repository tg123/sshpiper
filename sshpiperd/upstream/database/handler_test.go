package database

import (
	"testing"
	"log"
	"os"
	"net"
	"fmt"

	//"github.com/gokyle/sshkey"

	upstreamprovider "github.com/tg123/sshpiper/sshpiperd/upstream"
)

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

func TestFindUpstream(t *testing.T) {

	p := newTestPlugin(t)
	defer p.db.Close()

	h := p.GetHandler()
	//
	_, _, err := h(testconn{"abc11"})
	fmt.Println(err)
	db := p.db
	db.LogMode(true)
	db.SetLogger(log.New(os.Stdout,"", log.LstdFlags))

	db.Create(&downstream{
		Username: "abc111",
		AuthorizedKeys: []authorizedKey{
			{
				Key: key{
					Data: "AAAAB3NzaC1yc2EAAAADAQABAAABAQDGJw1E8RXlBUy88NT/JWh7b+ZlImB2ZuJDukSwnouo5MaqpvRf9jeOlWVpMQDIs31TUj97uuVJGjdtA42h1uosSb0DC7l78mmyDWCjB7Q+MCSu9yS1HtSu/0hMqyEGOX5FM7GyGwppTlU5Ji43QK0xSR3QjaJBfWrDyWrbBg6hFt1L+Yv+VLVVynFRwONpbO4hivT8P6bU5wmCt3cj+RT8vEv10lzaKDlciMaD8QDStC0Qjj0II0+fmgK33eJHZtHqj5edqAZgKBwxVjStzML9p6M1+3N24Dv86Ktna+5wF3f0Rg8JmS/yhhukt1+r9ZTgv1oR2l9W7aqEAGSnb95h",
					Type: "rsa",
				},
			},
		},
		Upstream: upstream{
			Username:    "bcd",
			AuthMapType: authMapTypePrivateKey,
			PrivateKey: privateKey{
				Key: key{
					Data: `AAAAB3NzaC1yc2EAAAADAQABAAABAQDGJw1E8RXlBUy88NT`,
					Type: "rsa",
				},
			},
			Server: server{
				Address:       "123",
				IgnoreHostKey: true,
			},
		},
	})

}
