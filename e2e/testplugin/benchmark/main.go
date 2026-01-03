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

// testprivatekey matches the public key preloaded into host-publickey for e2e.
const testprivatekey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDURkx99uaw1KddraZcLpB5kfMrWwvUz2fPOoArLcpz9QAAAJC+j0+Svo9P
kgAAAAtzc2gtZWQyNTUxOQAAACDURkx99uaw1KddraZcLpB5kfMrWwvUz2fPOoArLcpz9Q
AAAEDcQgdh2z2r/6blq0ziJ1l6s6IAX8C+9QHfAH931cHNO9RGTH325rDUp12tplwukHmR
8ytbC9TPZ886gCstynP1AAAADWJvbGlhbkB1YnVudHU=
`

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
				Name:    "private-key",
				Usage:   "private key for upstream auth (PEM)",
				EnvVars: []string{"SSHPIPERD_BENCH_PRIVATE_KEY"},
				Value:   testprivatekey,
			},
			&cli.StringFlag{
				Name:    "private-key-file",
				Usage:   "private key file for upstream auth (PEM)",
				EnvVars: []string{"SSHPIPERD_BENCH_PRIVATE_KEY_FILE"},
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			target := c.String("target")
			privateKey := c.String("private-key")
			if keyfile := c.String("private-key-file"); keyfile != "" {
				keydata, err := os.ReadFile(keyfile)
				if err != nil {
					return nil, fmt.Errorf("failed to read private key file: %w", err)
				}

				privateKey = string(keydata)
			}

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
