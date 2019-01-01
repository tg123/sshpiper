package upstream

import (
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/tg123/sshpiper/sshpiperd/registry"
)

// Handler will be installed into sshpiper and help to establish the connection to upstream
// the returned auth pipe is to map/convert downstream auth method to another auth for
// connecting to upstream.
// e.g. map downstream public key to another upstream private key
type Handler func(conn ssh.ConnMetadata) (net.Conn, *ssh.AuthPipe, error)

type CreatePipeOption struct {

}

// Provider is a factory for Upstream Provider
type Provider interface {
	registry.Plugin

	GetHandler() Handler

	CreatePipe(opt CreatePipeOption) error

	RemovePipe(name string) error
}

var (
	drivers = registry.NewRegistry()
)

// Register adds an upstream provider with given name to registry
func Register(name string, driver Provider) {
	drivers.Register(name, driver)
}

// All return all registered upstream providers
func All() []string {
	return drivers.Drivers()
}

// Get returns an upstream provider by name, return nil if not found
func Get(name string) Provider {
	if d, ok := drivers.Get(name).(Provider); ok {
		return d

	}

	return nil
}
