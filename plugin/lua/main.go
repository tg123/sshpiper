//go:build full || e2e

package main

import (
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {
	plugin := newLuaPlugin()

	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "lua",
		Usage: "sshpiperd lua plugin - route SSH connections using Lua scripts",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "script",
				Usage:       "path to lua script file",
				Required:    true,
				EnvVars:     []string{"SSHPIPERD_LUA_SCRIPT"},
				Destination: &plugin.ScriptPath,
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			return plugin.CreateConfig()
		},
	})
}
