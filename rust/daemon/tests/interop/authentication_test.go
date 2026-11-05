//go:build rustdaemon

package interop_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"google.golang.org/grpc"
)

func servePlugin(t *testing.T, config libplugin.SshPiperPluginConfig) []string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	plugin, err := libplugin.NewFromGrpc(config, server, listener)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- plugin.Serve() }()
	t.Cleanup(func() {
		server.Stop()
		listener.Close()
		if err := <-stopped; err != nil {
			t.Errorf("plugin shutdown: %v", err)
		}
	})
	return []string{"grpc", "--endpoint", listener.Addr().String(), "--insecure"}
}

func TestRustDaemonUpstreamSignatureNegotiation(t *testing.T) {
	daemon := os.Getenv("SSHPIPERD_RUST_DAEMON")
	if daemon == "" {
		t.Fatal("SSHPIPERD_RUST_DAEMON must name a built binary")
	}
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	host, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	hostPEM, err := ssh.MarshalPrivateKey(hostPrivate, "")
	if err != nil {
		t.Fatal(err)
	}
	hostCertificate := &ssh.Certificate{
		Key: host.PublicKey(), CertType: ssh.HostCert,
		ValidPrincipals: []string{"127.0.0.1"}, ValidBefore: ssh.CertTimeInfinity,
	}
	if err := hostCertificate.SignCert(rand.Reader, host); err != nil {
		t.Fatal(err)
	}
	certifiedHost, err := ssh.NewCertSigner(hostCertificate, host)
	if err != nil {
		t.Fatal(err)
	}
	hostChecker := &ssh.CertChecker{
		IsHostAuthority: func(authority ssh.PublicKey, _ string) bool {
			return bytes.Equal(authority.Marshal(), host.PublicKey().Marshal())
		},
	}
	rsaPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	upstreamSigner, err := ssh.NewSignerFromKey(rsaPrivate)
	if err != nil {
		t.Fatal(err)
	}
	mappingKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivate)})
	for _, scenario := range []string{"sha256-only", "sha512-only", "rejected-key", "connection-failure", "publickey-chain", "unsigned-offer"} {
		t.Run(scenario, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { listener.Close() })
			upstreamAddress := listener.Addr().String()
			var connections atomic.Int32
			signatureAlgorithm := ssh.KeyAlgoRSASHA256
			if scenario == "sha512-only" {
				signatureAlgorithm = ssh.KeyAlgoRSASHA512
			}
			server := &ssh.ServerConfig{
				Config:                  ssh.Config{KeyExchanges: []string{ssh.KeyExchangeMLKEM768X25519}},
				PublicKeyAuthAlgorithms: []string{signatureAlgorithm},
				PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
					if scenario == "rejected-key" || meta.User() != "mapped-user" || !bytes.Equal(key.Marshal(), upstreamSigner.PublicKey().Marshal()) {
						return nil, fmt.Errorf("key rejected")
					}
					return nil, nil
				},
			}
			server.AddHostKey(certifiedHost)
			if scenario == "connection-failure" {
				listener.Close()
			} else {
				go func() {
					for {
						connection, err := listener.Accept()
						if err != nil {
							return
						}
						connections.Add(1)
						go func() {
							defer connection.Close()
							_, channels, requests, err := ssh.NewServerConn(connection, server)
							if err != nil {
								return
							}
							go ssh.DiscardRequests(requests)
							for channel := range channels {
								channel.Reject(ssh.UnknownChannelType, "no channels")
							}
						}()
					}
				}()
			}
			type notice struct {
				method  string
				allowed []string
			}
			notices := make(chan notice, 8)
			var offers, passwords atomic.Int32
			chained := scenario == "publickey-chain" || scenario == "unsigned-offer"
			passwordPlugin := servePlugin(t, libplugin.SshPiperPluginConfig{
				PasswordCallback: func(meta libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
					passwords.Add(1)
					if string(password) != "downstream-password" || (chained && meta.GetMeta("verified-key") != "yes") {
						return nil, fmt.Errorf("wrong password or missing chain metadata")
					}
					return &libplugin.Upstream{
						Uri:            "tcp://" + upstreamAddress,
						UserName:       "mapped-user",
						KnownHostsData: []byte("@cert-authority " + knownhosts.Line([]string{upstreamAddress}, host.PublicKey()) + "\n"),
						Auth: &libplugin.Upstream_PrivateKey{
							PrivateKey: &libplugin.UpstreamPrivateKeyAuth{PrivateKey: mappingKey},
						},
					}, nil
				},
				UpstreamAuthFailureCallback: func(_ libplugin.ConnMetadata, method string, _ error, allowed []string) {
					notices <- notice{method, slices.Clone(allowed)}
				},
			})
			pluginArgs := passwordPlugin
			var auth []ssh.AuthMethod
			if chained {
				keyPlugin := servePlugin(t, libplugin.SshPiperPluginConfig{
					PublicKeyCallback: func(_ libplugin.ConnMetadata, key []byte) (*libplugin.Upstream, error) {
						offers.Add(1)
						if !bytes.Equal(key, host.PublicKey().Marshal()) {
							return nil, fmt.Errorf("unexpected downstream key")
						}
						return &libplugin.Upstream{
							Auth: &libplugin.Upstream_NextPlugin{
								NextPlugin: &libplugin.UpstreamNextPluginAuth{Meta: map[string]string{"verified-key": "yes"}},
							},
						}, nil
					},
				})
				pluginArgs = append(append(keyPlugin, "--"), passwordPlugin...)
				signer := host
				if scenario == "unsigned-offer" {
					signer = unsignedSigner{host}
				}
				auth = append(auth, ssh.PublicKeys(signer))
			}
			auth = append(auth, ssh.Password("downstream-password"))
			temp := t.TempDir()
			keyPath := filepath.Join(temp, "host-key")
			if err := os.WriteFile(keyPath, pem.EncodeToMemory(hostPEM), 0o600); err != nil {
				t.Fatal(err)
			}
			address := freeAddress(t)
			_, port, _ := net.SplitHostPort(address)
			args := append([]string{
				"--address", "127.0.0.1", "--port", port, "--server-key", keyPath,
				"--server-cert-data", base64.StdEncoding.EncodeToString(ssh.MarshalAuthorizedKey(hostCertificate)),
			}, pluginArgs...)
			startDaemon(t, exec.Command(daemon, args...), address)
			client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{
				User: "downstream-user", Auth: auth,
				Config:          ssh.Config{KeyExchanges: []string{ssh.KeyExchangeMLKEM768X25519}},
				HostKeyCallback: hostChecker.CheckHostKey, Timeout: 10 * time.Second,
			})
			wantSuccess := scenario != "rejected-key" && scenario != "connection-failure" && scenario != "unsigned-offer"
			if client != nil {
				client.Close()
			}
			if (err == nil) != wantSuccess {
				t.Fatalf("authentication: err=%v, want success=%v", err, wantSuccess)
			}
			if scenario == "rejected-key" {
				select {
				case notice := <-notices:
					if notice.method != "publickey" || !slices.Equal(notice.allowed, []string{"publickey"}) {
						t.Fatalf("incorrect upstream failure metadata: %+v", notice)
					}
				default:
					t.Fatal("missing upstream authentication failure notice")
				}
			}
			if len(notices) != 0 {
				t.Fatal("unexpected upstream authentication failure notice")
			}
			if chained && offers.Load() != 1 {
				t.Fatalf("unsigned and signed requests must reuse selection: got %d callbacks", offers.Load())
			}
			if scenario == "unsigned-offer" && (connections.Load() != 0 || passwords.Load() != 0) {
				t.Fatalf("unsigned offer advanced authentication: %d upstream connections, %d password callbacks", connections.Load(), passwords.Load())
			}
		})
	}
}

type unsignedSigner struct{ ssh.Signer }

func (unsignedSigner) Sign(_ io.Reader, _ []byte) (*ssh.Signature, error) {
	return nil, fmt.Errorf("intentional unsigned-offer regression")
}
