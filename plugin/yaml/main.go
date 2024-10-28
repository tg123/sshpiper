//go:build full || e2e

package main

import (
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {
	plugin := newYamlPlugin()

	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "yaml",
		Usage: "sshpiperd yaml plugin",
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:        "config",
				Usage:       "path to yaml config files, can be globs as well",
				Required:    true,
				EnvVars:     []string{"SSHPIPERD_YAML_CONFIG"},
				Destination: &plugin.FileGlobs,
			},
			&cli.BoolFlag{
				Name:        "no-check-perm",
				Usage:       "disable 0400 checking",
				EnvVars:     []string{"SSHPIPERD_YAML_NOCHECKPERM"},
				Destination: &plugin.NoCheckPerm,
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			skel := libplugin.NewSkelPlugin(plugin.listPipe)
			return skel.CreateConfig(), nil
		},
	})
}
