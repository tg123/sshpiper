//go:build e2e

package main

import (
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
	"log/slog"
)

func main() {
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name: "getmeta",
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			return &libplugin.SshPiperPluginConfig{
				PasswordCallback: func(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
					target := conn.GetMeta("targetaddr")

					host, port, err := libplugin.SplitHostPortForSSH(target)
					if err != nil {
						return nil, err
					}

					slog.Info("routing", "target", target)
					return &libplugin.Upstream{
						Host:          host,
						Port:          int32(port),
						IgnoreHostKey: true,
						Auth:          libplugin.CreatePasswordAuth(password),
					}, nil
				},
			}, nil
		},
	})
}
