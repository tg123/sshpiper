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
type Handler func(conn ssh.ConnMetadata, challengeContext ssh.AdditionalChallengeContext) (net.Conn, *ssh.AuthPipe, error)

// CreatePipeOption contains options for creating a pipe to upstream
type CreatePipeOption struct {
	Username         string
	UpstreamUsername string
	Host             string
	Port             int
}

// Pipe is a connection which linked downstream and upstream
// SSHPiper searches pipe base on username
type Pipe struct {
	Username         string
	UpstreamUsername string
	Host             string
	Port             int
}

// PipeManager manages pipe inside upstream
type PipeManager interface {

	// Return All pipes inside upstream
	ListPipe() ([]Pipe, error)

	// Create a pipe inside upstream
	CreatePipe(opt CreatePipeOption) error

	// Remove a pipe from upstream
	RemovePipe(name string) error
}

// Provider is a factory for Upstream Provider
type Provider interface {
	registry.Plugin
	PipeManager

	GetHandler() Handler
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

// SplitHostPortForSSH is the modified version of net.SplitHostPort but return port 22 is no port is specified
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
		if _, _, err = net.SplitHostPort(host + ":22"); err == nil {
			port = 22
		}
	}

	if host == "" {
		err = fmt.Errorf("empty addr")
	}

	return
}

// DialForSSH is the modified version of net.Dial, would add ":22" automaticlly
func DialForSSH(addr string) (net.Conn, error) {

	if _, _, err := net.SplitHostPort(addr); err != nil && addr != "" {
		// test valid after concat :22
		if _, _, err := net.SplitHostPort(addr + ":22"); err == nil {
			addr += ":22"
		}
	}

	return net.Dial("tcp", addr)
}
