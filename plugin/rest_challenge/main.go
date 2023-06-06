package main

import (
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main(){

	plugin := newRestChallengePlugin()

	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "rest_challenge",
		Usage: "sshpiperd rest_challenge --url https://localhost:8443/challenge",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:				"url",
				Usage:   		"URL to a REST endpoint (ie. https://domain.com/v1/sshpiperd/challenge) to challenge the connection",
				Value:   		"https://localhost:8443/challenge",
				EnvVars: []string{"REST_CHALLENGE_URL"},
				Destination: &plugin.URL,
			},
			&cli.BoolFlag{
				Name:        "insecure",
				Usage:       "Disable SSL/TLS verification on challenge endpoint",
				EnvVars:     []string{"REST_CHALLENGE_INSECURE"},
				Destination: &plugin.Insecure,
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			return &libplugin.SshPiperPluginConfig{
				KeyboardInteractiveCallback: func(conn libplugin.ConnMetadata, client libplugin.KeyboardInteractiveChallenge) (*libplugin.Upstream, error) {		
					return plugin.challenge(conn, client)
				},
			}, nil
		},
	})
}
