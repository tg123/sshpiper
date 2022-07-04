package main

import (
	"fmt"
	"path"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func createWorkingdir(c *cli.Context, user string) (*workingdir, error) {
	if !c.Bool("allow-baduser-name") {
		if !isUsernameSecure(user) {
			return nil, fmt.Errorf("bad username: %s", user)
		}
	}

	root := c.String("root")

	return &workingdir{
		path:        path.Join(root, user),
		noCheckPerm: c.Bool("no-check-perm"),
		strict:      c.Bool("strict-hostkey"),
	}, nil
}

func main() {

	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "workingdir",
		Usage: "sshpiperd workingdir plugin",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "root",
				Usage:   "path to root working directory",
				Value:   "/var/sshpiper",
				EnvVars: []string{"SSHPIPERD_WORKINGDIR_ROOT"},
			},
			&cli.BoolFlag{
				Name:    "allow-baduser-name",
				Usage:   "allow bad username",
				EnvVars: []string{"SSHPIPERD_WORKINGDIR_ALLOWBADUSERNAME"},
			},
			&cli.BoolFlag{
				Name:    "no-check-perm",
				Usage:   "disable 0400 checking",
				EnvVars: []string{"SSHPIPERD_WORKINGDIR_NOCHECKPERM"},
			},
			// &cli.StringFlag{
			// 	Name:    "fallback-username",
			// 	Usage:   "fallback to a user when user does not exists in directory",
			// 	EnvVars: []string{"SSHPIPERD_WORKINGDIR_FALLBACKUSERNAME"},
			// },
			&cli.BoolFlag{
				Name:    "strict-hostkey",
				Usage:   "upstream host public key must be in known_hosts file, otherwise drop the connection",
				EnvVars: []string{"SSHPIPERD_WORKINGDIR_STRICTHOSTKEY"},
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {

			return &libplugin.SshPiperPluginConfig{
				PasswordCallback: func(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
					w, err := createWorkingdir(c, conn.User())
					if err != nil {
						return nil, err
					}

					u, err := w.createUpstream()
					if err != nil {
						return nil, err
					}

					u.Auth = libplugin.CreatePasswordAuth(password)
					return u, nil
				},

				PublicKeyCallback: func(conn libplugin.ConnMetadata, key []byte) (*libplugin.Upstream, error) {
					w, err := createWorkingdir(c, conn.User())
					if err != nil {
						return nil, err
					}

					u, err := w.createUpstream()
					if err != nil {
						return nil, err
					}

					k, err := w.mapkey(key)
					u.Auth = libplugin.CreatePrivateKeyAuth(k)

					return u, nil
				},

				VerifyHostKeyCallback: func(conn libplugin.ConnMetadata, key []byte) (bool, error) {
					return true, nil
				},
			}, nil
		},
	})
}
