package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"

	"github.com/tg123/sshpiper/plugin/internal/workingdir"

	log "github.com/sirupsen/logrus"
)

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
			&cli.BoolFlag{
				Name:    "strict-hostkey",
				Usage:   "upstream host public key must be in known_hosts file, otherwise drop the connection",
				EnvVars: []string{"SSHPIPERD_WORKINGDIR_STRICTHOSTKEY"},
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {

			root := c.String("root")

			return &libplugin.SshPiperPluginConfig{
				PublicKeyCallback: func(conn libplugin.ConnMetadata, key []byte) (*libplugin.Upstream, error) {

					userdir := path.Join(root, conn.User())

					var upstream *libplugin.Upstream

					_ = filepath.Walk(userdir, func(path string, info os.FileInfo, err error) error {

						log.Infof("search public key in path: %v", path)
						if err != nil {
							log.Infof("error walking path: %v", err)
							return nil
						}

						if !info.IsDir() {
							return nil
						}

						w := &workingdir.Workingdir{
							Path:        path,
							NoCheckPerm: c.Bool("no-check-perm"),
							Strict:      false,
						}

						u, err := w.CreateUpstream()
						if err != nil {
							return nil
						}

						k, err := w.Mapkey(key)
						if err != nil {
							return nil
						}

						u.Auth = libplugin.CreatePrivateKeyAuth(k)
						upstream = u
						return fmt.Errorf("stop")
					})

					if upstream != nil {
						return upstream, nil
					}

					return nil, fmt.Errorf("no matching public key found in %v", userdir)
				},
			}, nil
		},
	})
}
