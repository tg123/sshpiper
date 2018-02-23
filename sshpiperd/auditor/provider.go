package auditor

import (
	"golang.org/x/crypto/ssh"

	"github.com/tg123/sshpiper/sshpiperd/registry"
)

// Hook is called after ssh connection pipe is established and all msg will be
// put into the hook and msg will be converted to the return value of this func
type Hook func(conn ssh.ConnMetadata, msg []byte) ([]byte, error)

// Auditor holds Hooks for upstream and downstream
type Auditor interface {

	// All msg between piper and upstream will be put into the hook
	// nil for ignore
	GetUpstreamHook() Hook

	// All msg between piper and downstream will be put into the hook
	// nil for ignore
	GetDownstreamHook() Hook

	// Will be called when connection closed
	Close() error
}

// Provider is a factory for Auditor
type Provider interface {
	registry.Plugin

	// Will be called when piped connection established
	// nil for no Auditor needed for this connection
	Create(ssh.ConnMetadata) (Auditor, error)
}

var (
	drivers = registry.NewRegistry()
)

// Register adds an auditor with given name to registry
func Register(name string, driver Provider) {
	drivers.Register(name, driver)
}

// All return all registered auditors
func All() []string {
	return drivers.Drivers()
}

// Get returns an auditor by name, return nil if not found
func Get(name string) Provider {
	if d, ok := drivers.Get(name).(Provider); ok {
		return d

	}

	return nil
}
