//go:build e2e

package main

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"net/rpc"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
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
			&cli.StringFlag{
				Name:     "testremotekey",
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

			keydata, err := base64.StdEncoding.DecodeString(c.String("testremotekey"))
			if err != nil {
				return nil, err
			}

			key, err := ssh.ParseRawPrivateKey(keydata)
			if err != nil {
				return nil, err
			}

			_, ok := key.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("key format not supported")
			}

			return &libplugin.SshPiperPluginConfig{
				NewConnectionCallback: func(conn libplugin.ConnMetadata) error {
					return rpcclient.Call("TestPlugin.NewConnection", "", nil)
				},
				NextAuthMethodsCallback: func(conn libplugin.ConnMetadata) ([]string, error) {
					var methods []string
					if err := rpcclient.Call("TestPlugin.NextAuthMethods", "", &methods); err != nil {
						return nil, err
					}
					return methods, nil
				},
				BannerCallback: func(conn libplugin.ConnMetadata) string {
					var banner string
					_ = rpcclient.Call("TestPlugin.Banner", "", &banner)
					return banner
				},
				VerifyHostKeyCallback: func(conn libplugin.ConnMetadata, hostname, netaddr string, key []byte) error {
					args := map[string]string{
						"hostname": hostname,
						"netaddr":  netaddr,
						"key":      string(key),
					}
					return rpcclient.Call("TestPlugin.VerifyHostKey", args, nil)
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
						Auth:          libplugin.CreateRemoteSignerAuth("testplugin"),
						IgnoreHostKey: false,
					}, nil
				},
				GrpcRemoteSignerFactory: func(metadata string) (crypto.Signer, error) {
					if metadata != "testplugin" {
						return nil, fmt.Errorf("metadata mismatch")
					}

					return key.(crypto.Signer), nil
				},
			}, nil
		},
	})
}
