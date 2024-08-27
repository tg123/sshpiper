//go:build full || e2e

package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {

	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "fixed",
		Usage: "sshpiperd fixed plugin, only password auth is supported",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "target",
				Usage:    "target ssh endpoint address",
				EnvVars:  []string{"SSHPIPERD_FIXED_TARGET"},
				Required: true,
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			target := c.String("target")
			host, port, err := libplugin.SplitHostPortForSSH(target)
			if err != nil {
				return nil, err
			}

			return &libplugin.SshPiperPluginConfig{
				PublicKeyCallback: func(conn libplugin.ConnMetadata, key []byte) (*libplugin.Upstream, error) {
					log.Info("routing to ", target)
					log.Info("username = ", conn.User())
					log.Infof("Attempting to route connection to target: %s", target)
					log.Infof("Connection metadata: User=%s, ClientVersion=%s, ServerVersion=%s", conn.User(), conn.UniqueID(), conn.RemoteAddr())
					log.Infof("Public Key Length: %d bytes", len(key))
					return &libplugin.Upstream{
						Host:          host,
						Port:          int32(port),
						UserName:      conn.User(),
						Auth:          libplugin.CreatePrivateKeyAuth(key),
						IgnoreHostKey: true,
					}, nil
				},
			}, nil
		},
	})
}
