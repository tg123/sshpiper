package main

import (
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
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
			&cli.BoolFlag{
				Name:    "no-password-auth",
				Usage:   "disable password authentication and only use public key authentication",
				EnvVars: []string{"SSHPIPERD_WORKINGDIR_NOPASSWORD_AUTH"},
			},
			&cli.BoolFlag{
				Name:    "recursive-search",
				Usage:   "search subdirectories under user directory for upsteam",
				EnvVars: []string{"SSHPIPERD_WORKINGDIR_RECURSIVESEARCH"},
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {

			fac := workdingdirFactory{
				root:             c.String("root"),
				allowBadUsername: c.Bool("allow-baduser-name"),
				noPasswordAuth:   c.Bool("no-password-auth"),
				noCheckPerm:      c.Bool("no-check-perm"),
				strictHostKey:    c.Bool("strict-hostkey"),
				recursiveSearch:  c.Bool("recursive-search"),
			}

			skel := libplugin.NewSkelPlugin(fac.listPipe)
			config := skel.CreateConfig()
			config.NextAuthMethodsCallback = func(_ libplugin.ConnMetadata) ([]string, error) {
				if fac.noPasswordAuth {
					return []string{"publickey"}, nil
				}

				return []string{"password", "publickey"}, nil
			}
			return config, nil
		},
	})
}
