package mysql

import (
	"testing"
	"log"
	"os"
	"net"
)

func newTestPlugin() *plugin {
	p := plugin{}

	p.Config.User = "root"
	p.Config.Password = "root"
	p.Config.Dbname = "sshpiper"
	p.Config.Host = "192.168.188.42"
	p.Config.Port = 3306

	p.Init(log.New(os.Stdout, "", 0))

	return &p
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

	p := newTestPlugin()
	defer p.db.Close()

	h := p.GetHandler()

	h(testconn{"abc"})
}
