package main

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {

	app := &cli.App{
		Name:            "fixed",
		Usage:           "sshpiperd fixed plugin, only password auth is supported",
		HideHelpCommand: true,
		HideHelp:        true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "target",
				Usage:    "target ssh endpoint address",
				EnvVars:  []string{"SSHPIPERD_FIXED_TARGET"},
				Required: true,
			},
		},
		Writer:    os.Stderr,
		ErrWriter: os.Stderr,
		Action: func(c *cli.Context) error {
			target := c.String("target")

			host, port, err := libplugin.SplitHostPortForSSH(target)
			if err != nil {
				return err
			}

			config := libplugin.SshPiperPluginConfig{
				PasswordCallback: func(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
					log.Info("routing to ", target)
					return &libplugin.Upstream{
						Host:          host,
						Port:          int32(port),
						IgnoreHostKey: true,
						Auth:          libplugin.CreatePasswordAuth(password),
					}, nil

				},
			}

			p, err := libplugin.NewFromStdio(config)
			if err != nil {
				return err
			}

			libplugin.ConfigStdioLogrus(p, nil)

			log.Printf("starting fix routing to ssh endpoint %v (password only)", target)
			return p.Serve()
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "cannot start plugin: %v\n", err)
	}
}
