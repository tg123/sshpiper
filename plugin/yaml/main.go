package main

import (
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {

	plugin := newYamlPlugin()

	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "yaml",
		Usage: "sshpiperd yaml plugin",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "config",
				Usage:       "path to yaml config file",
				Required:    true,
				EnvVars:     []string{"SSHPIPERD_YAML_CONFIG"},
				Destination: &plugin.File,
			},
			&cli.BoolFlag{
				Name:        "no-check-perm",
				Usage:       "disable 0400 checking",
				EnvVars:     []string{"SSHPIPERD_YAML_NOCHECKPERM"},
				Destination: &plugin.NoCheckPerm,
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {

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

				VerifyHostKeyCallback: func(conn libplugin.ConnMetadata, hostname, netaddr string, key []byte) error {
					return plugin.verifyHostKey(conn, hostname, netaddr, key)
				},
			}, nil
		},
	})
}
