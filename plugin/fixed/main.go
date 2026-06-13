//go:build full || e2e

package main

import (
	"log/slog"

	"github.com/tg123/sshpiper/libplugin"
)

func main() {
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "fixed",
		Usage: "sshpiperd fixed plugin, only password auth is supported",
		Flags: []libplugin.Flag{
			&libplugin.StringFlag{
				Name:     "target",
				Usage:    "target ssh endpoint address",
				EnvVars:  []string{"SSHPIPERD_FIXED_TARGET"},
				Required: true,
			},
		},
		CreateConfig: func(c libplugin.CliContext) (*libplugin.SshPiperPluginConfig, error) {
			target := c.String("target")

			host, port, err := libplugin.SplitHostPortForSSH(target)
			if err != nil {
				return nil, err
			}

			return &libplugin.SshPiperPluginConfig{
				PasswordCallback: func(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
					slog.Info("routing", "target", target)
					return &libplugin.Upstream{
						Host: host,
						Port: int32(port),
						Auth: libplugin.CreatePasswordAuth(password),
					}, nil
				},
			}, nil
		},
	})
}
