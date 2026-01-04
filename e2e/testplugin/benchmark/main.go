//go:build full || e2e

package main

import (
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "benchmark",
		Usage: "benchmark helper plugin using key auth to a fixed upstream",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "target",
				Usage:    "target ssh endpoint address",
				EnvVars:  []string{"SSHPIPERD_BENCH_TARGET"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "private-key-file",
				Usage:    "private key file for upstream auth (PEM)",
				EnvVars:  []string{"SSHPIPERD_BENCH_PRIVATE_KEY_FILE"},
				Required: true,
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			target := c.String("target")
			keyfile := c.String("private-key-file")
			keydata, err := os.ReadFile(keyfile)
			if err != nil {
				return nil, fmt.Errorf("failed to read private key file: %w", err)
			}
			privateKey := string(keydata)

			if strings.TrimSpace(privateKey) == "" {
				return nil, fmt.Errorf("private key is empty")
			}

			host, port, err := libplugin.SplitHostPortForSSH(target)
			if err != nil {
				return nil, err
			}

			return &libplugin.SshPiperPluginConfig{
				PublicKeyCallback: func(conn libplugin.ConnMetadata, _ []byte) (*libplugin.Upstream, error) {
					log.Infof("routing to %s with key auth", target)
					return &libplugin.Upstream{
						UserName:      conn.User(),
						Host:          host,
						Port:          int32(port),
						IgnoreHostKey: true,
						Auth:          libplugin.CreatePrivateKeyAuth([]byte(privateKey)),
					}, nil
				},
			}, nil
		},
	})
}
