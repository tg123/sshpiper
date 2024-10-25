package main

import (
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "kubernetes",
		Usage: "sshpiperd kubernetes plugin",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:     "all-namespaces",
				Usage:    "To watch all namespaces in the cluster",
				EnvVars:  []string{"SSHPIPERD_KUBERNETES_ALL_NAMESPACES"},
				Required: false,
			},
			&cli.StringFlag{
				Name:     "kubeconfig",
				Usage:    "Path to kubeconfig file",
				EnvVars:  []string{"SSHPIPERD_KUBERNETES_KUBECONFIG", "KUBECONFIG"},
				Required: false,
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			plugin, err := newKubernetesPlugin(c.Bool("all-namespaces"), c.String("kubeconfig"))
			if err != nil {
				return nil, err
			}
			skel := libplugin.NewSkelPlugin(plugin.listPipe)
			return skel.CreateConfig(), nil
		},
	})
}
