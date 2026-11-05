//go:build full || e2e

package main

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"

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
				PasswordCallback: func(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
					slog.Info("routing", "target", target)
					return &libplugin.Upstream{
						Uri:  fmt.Sprintf("tcp://%v", net.JoinHostPort(host, strconv.Itoa(port))),
						Auth: libplugin.CreatePasswordAuth(password),
					}, nil
				},
			}, nil
		},
	})
}
