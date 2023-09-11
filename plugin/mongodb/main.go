package main

import (
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {

	plugin := newMongoDBPlugin()

	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "mongodb",
		Usage: "sshpiperd mongodb plugin",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "uri",
				Usage:       "mongodb connection string",
				Required:    true,
				EnvVars:     []string{"SSHPIPERD_MONGO_URI"},
				Destination: &plugin.URI,
			},
			&cli.StringFlag{
				Name:        "database",
				Usage:       "mongodb database name",
				Required:    true,
				EnvVars:     []string{"SSHPIPERD_MONGO_DATABASE"},
				Destination: &plugin.Database,
			},
			&cli.StringFlag{
				Name:        "collection",
				Usage:       "mongodb collection name",
				Required:    true,
				EnvVars:     []string{"SSHPIPERD_MONGO_COLLECTION"},
				Destination: &plugin.Collection,
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
