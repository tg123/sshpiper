package challenger

import (
	"golang.org/x/crypto/ssh"

	"github.com/tg123/sshpiper/sshpiperd/registry"
)

// Handler is the callback for additional challenger
// use args client ssh.KeyboardInteractiveChallenge to interact with downstream
// return bool to indicate whether if the challenge is passed
type Handler func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (ssh.AdditionalChallengeContext, error)

// Provider is a factory for Challenger
type Provider interface {
	registry.Plugin

	GetHandler() Handler
}

var (
	drivers = registry.NewRegistry()
)

// Register adds an challenger with given name to registry
func Register(name string, driver Provider) {
	drivers.Register(name, driver)
}

// All return all registered challenger
func All() []string {
	return drivers.Drivers()
}

// Get returns an challenger by name, return nil if not found
func Get(name string) Provider {
	if d, ok := drivers.Get(name).(Provider); ok {
		return d

	}

	return nil
}
