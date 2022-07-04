package libplugin

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
)

type PluginTemplate struct {
	Name         string
	Usage        string
	Flags        []cli.Flag
	CreateConfig func(c *cli.Context) (*SshPiperPluginConfig, error)
}

func CreateAndRunPluginTemplate(t *PluginTemplate) {
	app := &cli.App{
		Name:            t.Name,
		Usage:           t.Usage,
		Flags:           t.Flags,
		HideHelpCommand: true,
		HideHelp:        true,
		Writer:          os.Stderr,
		ErrWriter:       os.Stderr,
		Action: func(c *cli.Context) error {
			if t == nil {
				return fmt.Errorf("plugin template is nil")
			}

			if t.CreateConfig == nil {
				return fmt.Errorf("plugin template create config is nil")
			}

			config, err := t.CreateConfig(c)
			if err != nil {
				return err
			}

			p, err := NewFromStdio(*config)
			if err != nil {
				return err
			}

			ConfigStdioLogrus(p, nil)
			return p.Serve()
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "cannot start plugin: %v\n", err)
	}
}
