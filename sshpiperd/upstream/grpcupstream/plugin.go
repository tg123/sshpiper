package grpcupstream

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/tg123/remotesigner/grpcsigner"
	"github.com/tg123/sshpiper/sshpiperd/upstream"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type plugin struct {
	Config struct {
		Endpoint string `long:"upstream-grpc-endpoint" description:"grpc endpoint of the upstream" env:"SSHPIPERD_UPSTREAM_GRPC_ENDPOINT" ini-name:"upstream-grpc-endpoint"`
		Insecure bool   `long:"upstream-grpc-insecure" description:"disable secure grpc connection" env:"SSHPIPERD_UPSTREAM_GRPC_INSECURE" ini-name:"upstream-grpc-insecure"`
		CA       string `long:"upstream-grpc-ca" description:"ca file path" env:"SSHPIPERD_UPSTREAM_GRPC_CA" ini-name:"upstream-grpc-ca"`
		Cert     string `long:"upstream-grpc-cert" description:"certificate file path" env:"SSHPIPERD_UPSTREAM_GRPC_CERT" ini-name:"upstream-grpc-cert"`
		Key      string `long:"upstream-grpc-key" description:"key file path" env:"SSHPIPERD_UPSTREAM_GRPC_KEY" ini-name:"upstream-grpc-key"`
		Timeout  int    `long:"upstream-grpc-timeout" description:"grpc call timeout in second" default:"10" env:"SSHPIPERD_UPSTREAM_GRPC_TIMEOUT" ini-name:"upstream-grpc-timeout"`
	}

	logger             *log.Logger
	upstreamClient     UpstreamRegistryClient
	remotesignerClient grpcsigner.SignerClient
}

// The name of the Plugin
func (p *plugin) GetName() string {
	return "grpc"
}

func (p *plugin) GetOpts() interface{} {
	return &p.Config
}

func (p *plugin) Init(logger *log.Logger) error {
	p.logger = logger

	var secopt grpc.DialOption
	if p.Config.Insecure {
		secopt = grpc.WithInsecure()
	} else {

		clientCert, err := tls.LoadX509KeyPair(p.Config.Cert, p.Config.Key)
		if err != nil {
			return err
		}

		config := &tls.Config{
			Certificates: []tls.Certificate{clientCert},
		}

		if p.Config.CA != "" {
			ca, err := ioutil.ReadFile(p.Config.CA)
			if err != nil {
				return err
			}
			certPool := x509.NewCertPool()
			if !certPool.AppendCertsFromPEM(ca) {
				return fmt.Errorf("failed to append ca")
			}

			config.RootCAs = certPool
		}

		secopt = grpc.WithTransportCredentials(credentials.NewTLS(config))
	}

	conn, err := grpc.Dial(p.Config.Endpoint, secopt, grpc.WithBlock())
	if err != nil {
		return err
	}

	p.upstreamClient = NewUpstreamRegistryClient(conn)
	p.remotesignerClient = grpcsigner.NewSignerClient(conn)

	return nil
}

func (p *plugin) GetHandler() upstream.Handler {
	return p.findUpstream
}

func init() {
	upstream.Register("grpc", &plugin{})
}
