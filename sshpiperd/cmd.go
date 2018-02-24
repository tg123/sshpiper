package main

import (
	"fmt"
	"os"

	"github.com/gokyle/sshkey"
	"github.com/jessevdk/go-flags"

	"github.com/tg123/sshpiper/sshpiperd/auditor"
	"github.com/tg123/sshpiper/sshpiperd/challenger"
	"github.com/tg123/sshpiper/sshpiperd/registry"
	"github.com/tg123/sshpiper/sshpiperd/upstream"
)

type subCommand struct{ callback func(args []string) error }

func (s *subCommand) Execute(args []string) error {
	return s.callback(args)
}

func addSubCommand(parser *flags.Parser, name, desc string, callback func(args []string) error) {
	_, err := parser.AddCommand(name, desc, "", &subCommand{callback})

	if err != nil {
		panic(err)
	}
}

func addOpt(parser *flags.Parser, name string, data interface{}) {
	_, err := parser.AddGroup(name, "", data)

	if err != nil {
		panic(err)
	}
}

func addPlugins(parser *flags.Parser, name string, pluginNames []string, getter func(n string) registry.Plugin) {
	for _, n := range pluginNames {

		p := getter(n)

		opt := p.GetOpts()

		if opt == nil {
			continue
		}

		_, err := parser.AddGroup(name+"."+p.GetName(), "", opt)

		if err != nil {
			panic(err)
		}
	}
}

func populateFromConfig(ini *flags.IniParser, data interface{}, longopt string) error {

	parser := flags.NewParser(data, flags.IgnoreUnknown)
	parser.Parse()

	o := parser.FindOptionByLongName(longopt)
	file := o.Value().(flags.Filename)
	err := ini.ParseFile(string(file))

	if err != nil {
		// set by user
		if !o.IsSetDefault() {
			return err
		}
	}

	return nil
}

func main() {

	parser := flags.NewNamedParser("sshpiperd", flags.Default)
	parser.SubcommandsOptional = true
	parser.LongDescription = "SSH Piper works as a proxy-like ware, and route connections by username, src ip , etc. Please see <https://github.com/tg123/sshpiper> for more information"

	// version
	addSubCommand(parser, "version", "show version", func(args []string) error {
		showVersion()
		return nil
	})

	dumpConfig := func() {
		ini := flags.NewIniParser(parser)
		ini.Write(os.Stdout, flags.IniIncludeDefaults)
	}

	// dumpini
	addSubCommand(parser, "dumpconfig", "dump current config ini to stdout", func(args []string) error {
		dumpConfig()
		return nil
	})

	// manpage
	addSubCommand(parser, "manpage", "write man page to stdout", func(args []string) error {
		parser.WriteManPage(os.Stdout)
		return nil
	})

	// plugins
	addSubCommand(parser, "plugins", "list support plugins, e.g. sshpiperd plugis upstream", func(args []string) error {

		output := func(all []string) {
			for _, p := range all {
				fmt.Println(p)
			}

		}

		if len(args) == 0 {
			args = []string{"upstream", "challenger", "auditor"}
		}

		for _, n := range args {
			switch n {
			case "upstream":
				output(upstream.All())
			case "challenger":
				output(challenger.All())
			case "auditor":
				output(auditor.All())
			}
		}

		return nil
	})

	// options, for snap only at the moment
	addSubCommand(parser, "options", "list all options", func(args []string) error {
		for _, g := range parser.Groups() {
			for _, o := range g.Options() {
				fmt.Println(o.LongName)
			}
		}

		return nil
	})

	// generate key tools
	addSubCommand(parser, "genkey", "generate a 2048 rsa key to stdout", func(args []string) error {
		key, err := sshkey.GenerateKey(sshkey.KEY_RSA, 2048)
		if err != nil {
			return err
		}

		out, err := sshkey.MarshalPrivate(key, "")
		if err != nil {
			return err
		}

		_, err = fmt.Fprint(os.Stdout, string(out))

		return err
	})

	config := &struct {
		piperdConfig

		loggerConfig

		// need to be shown in help, or will be moved to populate config
		ConfigFile flags.Filename `long:"config" description:"Config file path. Will be overwriten by arg options and environment variables" default:"/etc/sshpiperd.ini" env:"SSHPIPERD_CONFIG_FILE" no-ini:"true"`
	}{}

	addOpt(parser, "sshpiperd", config)

	addPlugins(parser, "upstream", upstream.All(), func(n string) registry.Plugin { return upstream.Get(n) })
	addPlugins(parser, "challenger", challenger.All(), func(n string) registry.Plugin { return challenger.Get(n) })
	addPlugins(parser, "auditor", auditor.All(), func(n string) registry.Plugin { return auditor.Get(n) })

	// populate by config
	ini := flags.NewIniParser(parser)
	err := populateFromConfig(ini, config, "config")
	if err != nil {
		fmt.Println(fmt.Sprintf("load config file failed %v", err))
		os.Exit(1)
	}

	parser.CommandHandler = func(command flags.Commander, args []string) error {

		// no subcommand called, start to serve
		if command == nil {

			if len(args) > 0 {
				return fmt.Errorf("unknown command %v", args)
			}

			showVersion()
			dumpConfig()

			return startPiper(&config.piperdConfig, config.createLogger())
		}

		return command.Execute(args)
	}

	parser.Parse()
}
