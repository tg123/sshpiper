//go:build full || e2e

package main

import (
	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/libplugin/skel"
)

func main() {
	plugin := newYamlPlugin()

	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "yaml",
		Usage: "sshpiperd yaml plugin",
		Flags: []libplugin.Flag{
			&libplugin.StringSliceFlag{
				Name:        "config",
				Usage:       "path to yaml config files, can be globs as well",
				Required:    true,
				EnvVars:     []string{"SSHPIPERD_YAML_CONFIG"},
				Destination: &plugin.FileGlobs,
			},
			&libplugin.BoolFlag{
				Name:        "no-check-perm",
				Usage:       "disable 0400 checking",
				EnvVars:     []string{"SSHPIPERD_YAML_NOCHECKPERM"},
				Destination: &plugin.NoCheckPerm,
			},
		},
		CreateConfig: func(c libplugin.CliContext) (*libplugin.SshPiperPluginConfig, error) {
			skel := skel.NewSkelPlugin(plugin.listPipe)
			return skel.CreateConfig(), nil
		},
	})
}
