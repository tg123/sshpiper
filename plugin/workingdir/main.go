package main

import (
	"fmt"
	"path"
	"strings"

	"github.com/pquerna/otp/totp"
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
			&cli.BoolFlag{
				Name:    "check-totp",
				Usage:   "check totp code for 2FA, totp file should be in user directory named `totp`",
				EnvVars: []string{"SSHPIPERD_WORKINGDIR_CHECKTOTP"},
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

			checktotp := c.Bool("check-totp")

			skel := libplugin.NewSkelPlugin(fac.listPipe)
			config := skel.CreateConfig()
			config.NextAuthMethodsCallback = func(conn libplugin.ConnMetadata) ([]string, error) {

				auth := []string{"publickey"}

				if !fac.noPasswordAuth {
					auth = append(auth, "password")
				}

				if checktotp {
					if conn.GetMeta("totp") != "checked" {
						auth = []string{"keyboard-interactive"}
					}

				}

				return auth, nil
			}

			config.KeyboardInteractiveCallback = func(conn libplugin.ConnMetadata, client libplugin.KeyboardInteractiveChallenge) (*libplugin.Upstream, error) {
				user := conn.User()

				if !fac.allowBadUsername {
					if !isUsernameSecure(user) {
						return nil, fmt.Errorf("bad username: %s", user)
					}
				}

				w := &workingdir{
					Path:        path.Join(fac.root, conn.User()),
					NoCheckPerm: fac.noCheckPerm,
				}

				secret, err := w.Readfile("totp")
				if err != nil {
					return nil, err
				}

				for {

					passcode, err := client("", "", "Authentication code:", true)
					if err != nil {
						return nil, err
					}

					if totp.Validate(passcode, strings.TrimSpace(string(secret))) {
						return &libplugin.Upstream{
							Auth: libplugin.CreateRetryCurrentPluginAuth(map[string]string{
								"totp": "checked",
							}),
						}, nil
					}

					_, _ = client("", "Wrong code, please try again", "", false)
				}
			}

			return config, nil
		},
	})
}
