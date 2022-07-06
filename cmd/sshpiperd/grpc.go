package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"

	"github.com/tg123/sshpiper/cmd/sshpiperd/internal/plugin"
	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func createNetGrpcPlugin(args []string) (grpcPlugin *plugin.GrpcPlugin, err error) {
	app := &cli.App{
		Name:            "grpc",
		Usage:           "sshpiperd grpc plugin",
		HideHelpCommand: true,
		HideHelp:        true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "endpoint",
				Usage:    "grpc endpoint address",
				EnvVars:  []string{"SSHPIPERD_GRPC_ENDPOINT"},
				Required: true,
			},
			&cli.BoolFlag{
				Name:    "insecure",
				Usage:   "disable tls",
				EnvVars: []string{"SSHPIPERD_GRPC_INSECURE"},
			},
			&cli.StringFlag{
				Name:    "key",
				Usage:   "grpc client key path",
				EnvVars: []string{"SSHPIPERD_GRPC_KEY"},
			},
			&cli.StringFlag{
				Name:    "cert",
				Usage:   "grpc client cert path",
				EnvVars: []string{"SSHPIPERD_GRPC_CERT"},
			},
			&cli.StringFlag{
				Name:    "cacert",
				Usage:   "grpc ca cert path",
				EnvVars: []string{"SSHPIPERD_GRPC_CACERT"},
			},
		},
		Action: func(c *cli.Context) error {

			var secopt grpc.DialOption
			if c.Bool("insecure") {
				secopt = grpc.WithTransportCredentials(insecure.NewCredentials())
			} else {

				clientCert, err := tls.LoadX509KeyPair(c.String("cert"), c.String("key"))
				if err != nil {
					return err
				}

				config := &tls.Config{
					Certificates: []tls.Certificate{clientCert},
				}

				cacert := c.String("cacert")
				if cacert != "" {
					ca, err := ioutil.ReadFile(cacert)
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

			conn, err := grpc.Dial(c.String("endpoint"), secopt, grpc.WithBlock())
			if err != nil {
				return err
			}

			grpcPlugin, err = plugin.DialGrpc(conn)
			if err != nil {
				return err
			}

			grpcPlugin.Name = fmt.Sprintf("grpc://%s", c.String("endpoint"))

			return nil
		},
	}

	if err := app.Run(args); err != nil {
		return nil, err
	}

	return grpcPlugin, nil
}
