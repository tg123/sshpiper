//go:build full || e2e

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
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
			&cli.StringFlag{
				Name:        "lua-path",
				Usage:       "additional Lua package.path entries (semicolon-separated patterns)",
				EnvVars:     []string{"SSHPIPERD_LUA_PATH"},
				Destination: &plugin.SearchPath,
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			// Create context for cleanup
			ctx, cancel := context.WithCancel(c.Context)
			plugin.cancelFunc = cancel

			// Register SIGHUP handler for reloading the Lua script
			go func() {
				sigChan := make(chan os.Signal, 1)
				signal.Notify(sigChan, syscall.SIGHUP)
				defer signal.Stop(sigChan)

				for {
					select {
					case <-ctx.Done():
						return
					case <-sigChan:
						log.Info("Received SIGHUP, reloading Lua script...")
						if err := plugin.reloadScript(); err != nil {
							log.Errorf("Failed to reload Lua script: %v", err)
						}
					}
				}
			}()

			return plugin.CreateConfig()
		},
	})
}
