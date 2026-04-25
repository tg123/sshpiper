package libadmin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// DialOptions configures how an admin client connects to a sshpiperd
// instance over gRPC. The zero value is valid: it uses an insecure
// connection, which is fine for trusted private networks but should not be
// used over the public internet.
type DialOptions struct {
	// Insecure disables TLS. When false, TLS is enabled and (if non-empty)
	// CertFile, KeyFile, and CAFile are loaded as a client certificate plus
	// the CA used to verify the server.
	Insecure bool
	CertFile string
	KeyFile  string
	CAFile   string
	// ServerName overrides the SNI / TLS verification hostname.
	ServerName string
}

// Dial connects to the sshpiperd admin gRPC endpoint at addr.
//
// The returned *grpc.ClientConn must be closed by the caller when no longer
// needed (typically wrapped in a Client and closed via Client.Close).
func Dial(addr string, opts DialOptions) (*grpc.ClientConn, error) {
	var dopt grpc.DialOption
	switch {
	case opts.Insecure:
		dopt = grpc.WithTransportCredentials(insecure.NewCredentials())
	default:
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: opts.ServerName,
		}
		if opts.CertFile != "" || opts.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("load admin client cert: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
		if opts.CAFile != "" {
			ca, err := os.ReadFile(opts.CAFile)
			if err != nil {
				return nil, fmt.Errorf("read admin CA: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(ca) {
				return nil, fmt.Errorf("invalid admin CA in %s", opts.CAFile)
			}
			tlsConfig.RootCAs = pool
		}
		dopt = grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))
	}

	return grpc.NewClient(addr, dopt)
}

// Client is a thin wrapper around the generated SshPiperAdminClient. It
// owns the underlying gRPC connection and exposes a small, ergonomic API
// for the aggregator and CLI.
type Client struct {
	Addr string
	conn *grpc.ClientConn
	rpc  SshPiperAdminClient
}

// NewClient dials addr and returns a Client. The caller owns the returned
// Client and must call Close when done.
func NewClient(addr string, opts DialOptions) (*Client, error) {
	conn, err := Dial(addr, opts)
	if err != nil {
		return nil, err
	}
	return &Client{Addr: addr, conn: conn, rpc: NewSshPiperAdminClient(conn)}, nil
}

// Close releases the underlying gRPC connection.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// RPC returns the raw generated gRPC client. Tests and advanced consumers
// can use this to call methods not yet wrapped with helpers.
func (c *Client) RPC() SshPiperAdminClient { return c.rpc }

// ServerInfo returns identifying metadata about the sshpiperd instance.
func (c *Client) ServerInfo(ctx context.Context) (*ServerInfoResponse, error) {
	return c.rpc.ServerInfo(ctx, &ServerInfoRequest{})
}

// ListSessions returns all live sessions on this sshpiperd instance.
func (c *Client) ListSessions(ctx context.Context) ([]*Session, error) {
	resp, err := c.rpc.ListSessions(ctx, &ListSessionsRequest{})
	if err != nil {
		return nil, err
	}
	return resp.GetSessions(), nil
}

// KillSession asks this sshpiperd instance to close session id.
func (c *Client) KillSession(ctx context.Context, id string) (bool, error) {
	resp, err := c.rpc.KillSession(ctx, &KillSessionRequest{Id: id})
	if err != nil {
		return false, err
	}
	return resp.GetKilled(), nil
}

// Discovery resolves the set of sshpiperd instances the admin tool should
// talk to. The aggregator calls Endpoints periodically (or on demand) so
// implementations may return a freshly-resolved list each time.
//
// A static, command-line-supplied list is the simplest implementation;
// future implementations could pull from DNS SRV records, Kubernetes
// services, or a service registry.
type Discovery interface {
	Endpoints(ctx context.Context) ([]string, error)
}

// StaticDiscovery returns a fixed list of endpoints — appropriate when the
// list of sshpiperd instances is supplied via CLI flags or a config file.
type StaticDiscovery struct {
	mu    sync.RWMutex
	addrs []string
}

// NewStaticDiscovery returns a StaticDiscovery populated with addrs.
func NewStaticDiscovery(addrs []string) *StaticDiscovery {
	d := &StaticDiscovery{}
	d.Set(addrs)
	return d
}

// Set replaces the discovery's endpoint list.
func (s *StaticDiscovery) Set(addrs []string) {
	cp := make([]string, len(addrs))
	copy(cp, addrs)
	s.mu.Lock()
	s.addrs = cp
	s.mu.Unlock()
}

// Endpoints implements Discovery.
func (s *StaticDiscovery) Endpoints(_ context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make([]string, len(s.addrs))
	copy(cp, s.addrs)
	return cp, nil
}
