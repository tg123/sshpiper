//go:build e2e

package main

import (
	"net"
	"net/rpc"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "testcreateconnplugin",
		Usage: "e2e test plugin only",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "rpcserver",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "testsshserver",
				Required: true,
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			rpcclient, err := rpc.Dial("tcp", c.String("rpcserver"))
			if err != nil {
				return nil, err
			}

			testsshserver := c.String("testsshserver")

			host, port, err := libplugin.SplitHostPortForSSH(testsshserver)
			if err != nil {
				return nil, err
			}

			return &libplugin.SshPiperPluginConfig{
				PasswordCallback: func(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
					return &libplugin.Upstream{
						Host: host,
						Port: int32(port),
						Auth: libplugin.CreatePasswordAuth(password),
					}, nil
				},
				// CreateConnCallback fully owns upstream connection creation:
				// the daemon delegates dialing to the plugin instead of using
				// its in-process net.Dial.
				CreateConnCallback: func(conn libplugin.ConnMetadata, uri string) (net.Conn, error) {
					if err := rpcclient.Call("TestPlugin.CreateConn", uri, nil); err != nil {
						return nil, err
					}

					return net.Dial("tcp", testsshserver)
				},
			}, nil
		},
	})
}
