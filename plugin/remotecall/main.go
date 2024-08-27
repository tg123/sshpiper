//go:build full || e2e

package main

import (
	"fmt"
	"strings"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/plugin/internal/remotecall"
	"github.com/urfave/cli/v2"
)

func createRemoteCaller(c *cli.Context) (*remotecall.RemoteCall, error) {
	remoteCall, err := remotecall.InitRemoteCall(
		c.String(userClusterEndpoint),
		c.Generic(remoteEndpoints).(*remotecall.StringMapFlag).Value,
		c.Path(mappingKeyPath),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating remote caller: %w", err)
	}

	return remoteCall, nil
}

func getUserName(response *remotecall.UserKeyAuthResponse) string {
	return strings.ToLower(string(response.PrincipalType)) + "." + response.PrincipalID
}

const (
	remoteEndpoints     = "remote-endpoint"
	userClusterEndpoint = "user-cluster-endpoint"
	mappingKeyPath      = "mapping-key-path"
)

func main() {
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "remote call",
		Usage: "sshpiperd remote plugin",
		Flags: []cli.Flag{
			&cli.GenericFlag{
				Name:     remoteEndpoints,
				Usage:    "path to remote endpoint for retrieving user's private key",
				EnvVars:  []string{"SSHPIPERD_PRIVATE_KEY_ENDPOINTS"},
				Value:    &remotecall.StringMapFlag{},
				Required: true,
			},
			&cli.StringFlag{
				Name:    userClusterEndpoint,
				Usage:   "endpoint for getting user to cluster mapping",
				EnvVars: []string{"SSHPIPERD_USER_MAPPING_ENDPOINT"},
			},
			&cli.PathFlag{
				Name:    mappingKeyPath,
				Usage:   "mapping key for upstream",
				EnvVars: []string{"SSHPIPERD_MAPPING_KEY_PATH"},
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			caller, err := createRemoteCaller(c)
			if err != nil {
				return nil, err
			}

			return &libplugin.SshPiperPluginConfig{

				NextAuthMethodsCallback: func(_ libplugin.ConnMetadata) ([]string, error) {
					return []string{"publickey"}, nil
				},

				PublicKeyCallback: func(conn libplugin.ConnMetadata, key []byte) (*libplugin.Upstream, error) {
					clusterName, err := caller.GetClusterName(conn.User())
					if err != nil {
						return nil, err
					}

					clusterURL, err := caller.GetUpstreamURL(clusterName)
					if err != nil {
						return nil, err
					}

					authResponse, err := caller.AuthenticateUser(key, clusterURL)
					if err != nil {
						return nil, err
					}

					k, err := caller.MapKey()
					if err != nil {
						return nil, err
					}

					host, port, err := libplugin.SplitHostPortForSSH(clusterURL)
					if err != nil {
						return nil, err
					}

					return &libplugin.Upstream{
						Host:     host,
						Port:     int32(port),
						UserName: getUserName(authResponse),
						Auth:     libplugin.CreatePrivateKeyAuth(k),
					}, nil
				},
			}, nil
		},
	})
}
