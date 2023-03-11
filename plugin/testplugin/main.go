//go:build e2e

package main

import (
	"net/rpc"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {

	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "testplugin",
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

			rpcclient, err := rpc.DialHTTP("tcp", c.String("rpcserver"))
			if err != nil {
				return nil, err
			}

			host, port, err := libplugin.SplitHostPortForSSH(c.String("testsshserver"))
			if err != nil {
				return nil, err
			}

			return &libplugin.SshPiperPluginConfig{
				NewConnectionCallback: func(conn libplugin.ConnMetadata) error {
					return rpcclient.Call("TestPlugin.NewConnection", "", nil)
				},
				PipeStartCallback: func(conn libplugin.ConnMetadata) {
					rpcclient.Call("TestPlugin.PipeStart", "", nil)
				},
				PipeErrorCallback: func(conn libplugin.ConnMetadata, err error) {
					rpcclient.Call("TestPlugin.PipeError", err.Error(), nil)
				},
				PasswordCallback: func(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
					var newpass string
					err := rpcclient.Call("TestPlugin.Password", string(password), &newpass)
					if err != nil {
						return nil, err
					}

					return &libplugin.Upstream{
						Host:          host,
						Port:          int32(port),
						Auth:          libplugin.CreatePasswordAuthFromString(newpass),
						IgnoreHostKey: true,
					}, nil
				},
			}, nil
		},
	})
}
