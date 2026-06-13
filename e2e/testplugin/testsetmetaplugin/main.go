//go:build e2e

package main

import (
	"github.com/tg123/sshpiper/libplugin"
)

func main() {
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name: "setmeta",
		Flags: []libplugin.Flag{
			&libplugin.StringFlag{
				Name:     "targetaddr",
				Required: true,
			},
		},
		CreateConfig: func(ctx libplugin.CliContext) (*libplugin.SshPiperPluginConfig, error) {
			return &libplugin.SshPiperPluginConfig{
				NoClientAuthCallback: func(conn libplugin.ConnMetadata) (*libplugin.Upstream, error) {
					return &libplugin.Upstream{
						Auth: libplugin.CreateNextPluginAuth(map[string]string{
							"targetaddr": ctx.String("targetaddr"),
						}),
					}, nil
				},
			}, nil
		},
	})
}
