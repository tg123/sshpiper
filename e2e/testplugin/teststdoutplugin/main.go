//go:build e2e

package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/tg123/sshpiper/libplugin"
)

// teststdoutplugin deliberately writes to stdout to emulate a common plugin
// authoring mistake. The sshpiperd <-> plugin gRPC transport runs over
// stdin/stdout, so accidental stdout writes from plugin code must not corrupt
// it. This plugin exercises the NewFromStdio safeguard that redirects
// os.Stdout to the plugin logger pipe once the transport is bound: the writes
// below happen inside callbacks (i.e. after the plugin is serving) and must
// not crash the gRPC connection. The redirected lines are forwarded to
// sshpiperd as plugin log messages over the Logs() gRPC stream.
func main() {
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name: "teststdout",
		Flags: []libplugin.Flag{
			&libplugin.StringFlag{
				Name:     "target",
				Required: true,
			},
		},
		CreateConfig: func(c libplugin.CliContext) (*libplugin.SshPiperPluginConfig, error) {
			target := c.String("target")

			host, port, err := libplugin.SplitHostPortForSSH(target)
			if err != nil {
				return nil, err
			}

			return &libplugin.SshPiperPluginConfig{
				PasswordCallback: func(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
					// accidental stdout writes while serving must be safe
					fmt.Println("teststdoutplugin: stdout write inside callback")
					fmt.Fprintln(os.Stdout, "teststdoutplugin: explicit os.Stdout write inside callback")
					slog.Info("routing", "target", target)
					return &libplugin.Upstream{
						Uri:  fmt.Sprintf("tcp://%s:%d", host, port),
						Auth: libplugin.CreatePasswordAuth(password),
					}, nil
				},
			}, nil
		},
	})
}
