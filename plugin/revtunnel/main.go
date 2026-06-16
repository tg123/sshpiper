//go:build full || e2e

package main

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

// idleTimeout is the hard-coded inactivity threshold after which a tunnel is
// evicted. Bumped on creation, every forwarded-tcpip channel open, and every
// byte that flows through an open channel.
const idleTimeout = 2 * time.Hour

// sweepInterval is how often the background sweeper checks for idle tunnels.
const sweepInterval = 5 * time.Minute

func main() {
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "revtunnel",
		Usage: "sshpiperd plugin that exposes ssh -R reverse tunnels under a generated guid",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "session-store",
				Usage:   "where to persist tunnel records (memory:// or file:///path/to/dir)",
				EnvVars: []string{"SSHPIPERD_REVTUNNEL_SESSION_STORE"},
				Value:   "memory://",
			},
			&cli.StringFlag{
				Name:    "host-key",
				Usage:   "path to an OpenSSH-format private key used by the in-process register-side ssh server; auto-generated ephemeral ed25519 key when empty",
				EnvVars: []string{"SSHPIPERD_REVTUNNEL_HOST_KEY"},
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			store, err := openSessionStore(c.String("session-store"))
			if err != nil {
				return nil, err
			}
			reg := newRegistry(store)

			srv, err := newRegisterServer(reg, c.String("host-key"))
			if err != nil {
				return nil, fmt.Errorf("revtunnel: start register-side ssh server: %w", err)
			}

			go runSweeper(reg, sweepInterval, idleTimeout)

			return buildPluginConfig(reg, srv), nil
		},
	})
}

func runSweeper(reg *registry, every, idle time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for range t.C {
		evicted := reg.EvictIdle(idle)
		for _, g := range evicted {
			slog.Info("revtunnel: evicted idle tunnel", "guid", g)
		}
	}
}
