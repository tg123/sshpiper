//go:build full || e2e

package main

import (
	"fmt"
	"os"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "testcaplugin",
		Usage: "Plugin to test ca public cert auth",
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
					if string(password) != "pass" {
						return nil, fmt.Errorf("Password is incorrect")
					}

					// Load the private key
					signer, err := os.ReadFile("/etc/ssh/ssh_user")
					if err != nil {
						return nil, fmt.Errorf("unable to read private key: %v", err)
					}

					// Load the public ca certificate
					capublickey, err := os.ReadFile("/etc/ssh/ssh_user-cert.pub")
					if err != nil {
						return nil, fmt.Errorf("unable to read ca cert: %v", err)
					}

					return &libplugin.Upstream{
						Host:          host,
						Port:          int32(port),
						IgnoreHostKey: true,
						Auth:          libplugin.CreatePrivateKeyAuth(signer, capublickey),
					}, nil
				},
			}, nil
		},
	})
}
