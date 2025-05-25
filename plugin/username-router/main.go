//go:build full || e2e

package main

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func parseTargetUser(raw string) (target string, username string, err error) {
	// Expect format: [target:port]+user
	parts := strings.SplitN(raw, "+", 2)
	if len(parts) != 2 {
		err = fmt.Errorf("invalid format (expected target:port+user)")
		return
	}

	target = parts[0]
	username = parts[1]
	return
}

func main() {

	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "username-router",
		Usage: "routing based on target inside username, format: 'target:port+realuser@sshpiper-host'",
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {

			return &libplugin.SshPiperPluginConfig{
				PasswordCallback: func(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {

					address, user, err := parseTargetUser(conn.User())
					if err != nil {
						return nil, fmt.Errorf("invalid username format %q: %w", conn.User(), err)
					}

					host, port, err := libplugin.SplitHostPortForSSH(address)
					if err != nil {
						return nil, fmt.Errorf("invalid target address %q: %w", address, err)
					}

					log.Info("routing to address ", address, " with user ", user)
					return &libplugin.Upstream{
						UserName:      user,
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
