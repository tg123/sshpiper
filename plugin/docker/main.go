package main

import (
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {

	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "docker",
		Usage: "sshpiperd docker plugin, see config in https://github.com/tg123/sshpiper/tree/master/plugin/docker",
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			plugin, err := newDockerPlugin()
			if err != nil {
				return nil, err
			}

			return &libplugin.SshPiperPluginConfig{

				NextAuthMethodsCallback: func(_ libplugin.ConnMetadata) ([]string, error) {
					return plugin.supportedMethods()
				},

				PasswordCallback: func(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
					return plugin.findAndCreateUpstream(conn, string(password), nil)
				},

				PublicKeyCallback: func(conn libplugin.ConnMetadata, key []byte) (*libplugin.Upstream, error) {
					return plugin.findAndCreateUpstream(conn, "", key)
				},
			}, nil
		},
	})
}
