package challenger

import (
	"golang.org/x/crypto/ssh"

	"github.com/tg123/sshpiper/sshpiperd/registry"
)

type ChallengerHandler func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (bool, error)

type Challenger interface {
	registry.Plugin

	GetChallengerHandler() ChallengerHandler
}

var (
	drivers = registry.NewRegistry()
)

func Register(name string, driver Challenger) {
	drivers.Register(name, driver)
}

func All() []string {
	return drivers.Drivers()
}

func Get(name string) Challenger {
	if d, ok := drivers.Get(name).(Challenger); ok {
		return d

	}

	return nil
}
