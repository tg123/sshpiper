package main

import (
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main(){

	plugin := newRestAuthPlugin()

	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "rest_auth",
		Usage: "sshpiperd rest_auth --url https://localhost:8443/challenge",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:				"url",
				Usage:   		"URL to a REST endpoint (ie. https://domain.com/v1/sshpiperd/challenge) to challenge the connection",
				Value:   		"https://localhost:8443/challenge",
				EnvVars: []string{"REST_AUTH_URL"},
				Destination: &plugin.URL,
			},
			&cli.BoolFlag{
				Name:        "insecure",
				Usage:       "Disable SSL/TLS verification on challenge endpoint",
				EnvVars:     []string{"REST_AUTH_INSECURE"},
				Destination: &plugin.Insecure,
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
					return nil
				},
			}, nil
		},
	})
}
