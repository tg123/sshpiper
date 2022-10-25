//go:build full

package main

import (
	"fmt"
	"path"
	"strings"

	"github.com/pquerna/otp/totp"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/plugin/internal/workingdir"
	"github.com/urfave/cli/v2"
)

// type secretLoader struct {
// }

// func (s *secretLoader) Load(user string) (string, error) {
// 	return "", nil
// }

// TODO remove dup code
func createWorkingdir(c *cli.Context, user string) (*workingdir.Workingdir, error) {
	if !c.Bool("allow-baduser-name") {
		if !workingdir.IsUsernameSecure(user) {
			return nil, fmt.Errorf("bad username: %s", user)
		}
	}

	root := c.String("root")

	return &workingdir.Workingdir{
		Path:        path.Join(root, user),
		NoCheckPerm: c.Bool("no-check-perm"),
		Strict:      c.Bool("strict-hostkey"),
	}, nil
}

func main() {
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "totp",
		Usage: "sshpiperd totp 2FA authentication, workingdir based",
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
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			return &libplugin.SshPiperPluginConfig{
				KeyboardInteractiveCallback: func(conn libplugin.ConnMetadata, client libplugin.KeyboardInteractiveChallenge) (*libplugin.Upstream, error) {

					w, err := createWorkingdir(c, conn.User())
					if err != nil {
						return nil, err
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
								Auth: libplugin.CreateNextPluginAuth(nil),
							}, nil
						}

						_, _ = client("", "Wrong code, please try again", "", false)
					}
				},
			}, nil
		},
	})
}
