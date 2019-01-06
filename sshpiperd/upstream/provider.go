package upstream

import (
	"fmt"
	"net"
	"strconv"

	"golang.org/x/crypto/ssh"

	"github.com/tg123/sshpiper/sshpiperd/registry"
)

// Handler will be installed into sshpiper and help to establish the connection to upstream
// the returned auth pipe is to map/convert downstream auth method to another auth for
// connecting to upstream.
// e.g. map downstream public key to another upstream private key
type Handler func(conn ssh.ConnMetadata) (net.Conn, *ssh.AuthPipe, error)

type CreatePipeOption struct {
	Username         string
	UpstreamUsername string
	Host             string
	Port             int
}

type Pipe struct {
	Username         string
	UpstreamUsername string
	Host             string
	Port             int
}

// Provider is a factory for Upstream Provider
type Provider interface {
	registry.Plugin

	GetHandler() Handler

	ListPipe() ([]Pipe, error)

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

func SplitHostPortForSSH(addr string) (host string, port int, err error) {
	host = addr
	h, p, err := net.SplitHostPort(host)
	if err == nil {
		host = h
		port, err = strconv.Atoi(p)

		if err != nil {
			return
		}
	} else if host != "" {
		// test valid after concat :22
		if _, _, err := net.SplitHostPort(host + ":22"); err == nil {
			port = 22
		}
	}

	if host == "" {
		err = fmt.Errorf("empty addr")
	}

	return
}
