package auditor

import (
	"golang.org/x/crypto/ssh"

	"github.com/tg123/sshpiper/sshpiperd/registry"
)

type AuditorHook func(conn ssh.ConnMetadata, msg []byte) ([]byte, error)

type Auditor interface {
	GetUpstreamHook() AuditorHook
	GetDownstreamHook() AuditorHook

	Close() error
}

type AuditorProvider interface {
	registry.Plugin

	CreateAuditor(ssh.ConnMetadata) (Auditor, error)
}

var (
	drivers = registry.NewRegistry()
)

func Register(name string, driver AuditorProvider) {
	drivers.Register(name, driver)
}

func All() []string {
	return drivers.Drivers()
}

func Get(name string) AuditorProvider {
	if d, ok := drivers.Get(name).(AuditorProvider); ok {
		return d

	}

	return nil
}
