package upstream

import (
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/tg123/sshpiper/sshpiperd/registry"
)

type UpstreamHandler func(conn ssh.ConnMetadata) (net.Conn, *ssh.SSHPiperAuthPipe, error)

type UpstreamProvider interface {
	registry.Plugin

	GetFindUpstreamHandle() UpstreamHandler
}

var (
	drivers = registry.NewRegistry()
)

func Register(name string, driver UpstreamProvider) {
	drivers.Register(name, driver)
}

func All() []string {
	return drivers.Drivers()
}

func Get(name string) UpstreamProvider {
	return drivers.Get(name).(UpstreamProvider)
}
