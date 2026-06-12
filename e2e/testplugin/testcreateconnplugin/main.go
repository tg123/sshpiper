//go:build e2e

package main

import (
	"net"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "testcreateconnplugin",
		Usage: "e2e test plugin only",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "testsshserver",
				Required: true,
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			testsshserver := c.String("testsshserver")

			return &libplugin.SshPiperPluginConfig{
				PasswordCallback: func(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
					return &libplugin.Upstream{
						// Deliberately bogus address: if the daemon dialed this
						// itself the connection would fail. The connection only
						// works because CreateConnCallback below dials the real
						// upstream, proving the plugin owns connection creation.
						Host: "192.0.2.1",
						Port: 1,
						Auth: libplugin.CreatePasswordAuth(password),
					}, nil
				},
				CreateConnCallback: func(conn libplugin.ConnMetadata, uri string) (net.Conn, error) {
					return net.Dial("tcp", testsshserver)
				},
			}, nil
		},
	})
}
