//go:build e2e

package main

import (
	"fmt"
	"net"
	"net/url"

	"github.com/google/uuid"
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

			// guid ties the Upstream uri returned by PasswordCallback to the
			// uri handed to CreateConnCallback, proving the plugin fully owns
			// connection creation: the daemon never dials anything itself, it
			// only passes our opaque uri back to us.
			guid := uuid.NewString()

			return &libplugin.SshPiperPluginConfig{
				PasswordCallback: func(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
					return &libplugin.Upstream{
						Uri:  fmt.Sprintf("testplugin://%v", guid),
						Auth: libplugin.CreatePasswordAuth(password),
					}, nil
				},
				CreateConnCallback: func(conn libplugin.ConnMetadata, uri string) (net.Conn, error) {
					u, err := url.Parse(uri)
					if err != nil {
						return nil, err
					}

					if u.Scheme != "testplugin" || u.Host != guid {
						return nil, fmt.Errorf("unexpected uri %q, want testplugin://%v", uri, guid)
					}

					return net.Dial("tcp", testsshserver)
				},
			}, nil
		},
	})
}
