package libplugin

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

type PluginTemplate struct {
	Name         string
	Usage        string
	Flags        []Flag
	CreateConfig func(c CliContext) (*SshPiperPluginConfig, error)
	ConfigLogger ConfigLogger
}

func CreateAndRunPluginTemplate(t *PluginTemplate) {
	if err := runPluginTemplate(t, os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "cannot start plugin: %v\n", err)
	}
}

func runPluginTemplate(t *PluginTemplate, args []string) error {
	if t == nil {
		return fmt.Errorf("plugin template is nil")
	}

	if t.CreateConfig == nil {
		return fmt.Errorf("plugin template create config is nil")
	}

	name := t.Name
	if name == "" && len(args) > 0 {
		name = filepath.Base(args[0])
	}

	var cmdArgs []string
	if len(args) > 0 {
		cmdArgs = args[1:]
	}

	c, err := parseFlags(name, t.Usage, t.Flags, cmdArgs)
	if err != nil {
		// help was requested: usage has already been printed, nothing to start.
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	config, err := t.CreateConfig(c)
	if err != nil {
		return err
	}

	p, err := NewFromStdio(*config)
	if err != nil {
		return err
	}

	configLogger := t.ConfigLogger
	if configLogger == nil {
		configLogger = ConfigLoggerSlog
	}
	p.SetConfigLoggerCallback(configLogger)
	return p.Serve()
}
