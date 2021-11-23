package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/jessevdk/go-flags"
	"github.com/tg123/sshkey"

	"github.com/tg123/sshpiper/sshpiperd/auditor"
	"github.com/tg123/sshpiper/sshpiperd/challenger"
	"github.com/tg123/sshpiper/sshpiperd/registry"
	"github.com/tg123/sshpiper/sshpiperd/upstream"
)

type subCommand struct{ callback func(args []string) error }

func (s *subCommand) Execute(args []string) error {
	return s.callback(args)
}

func addSubCommand(command *flags.Command, name, desc string, callback interface{}) *flags.Command {
	c, err := command.AddCommand(name, desc, "", callback)

	if err != nil {
		panic(err)
	}

	return c
}

func addOpt(group *flags.Group, name string, data interface{}) {
	_, err := group.AddGroup(name, "", data)

	if err != nil {
		panic(err)
	}
}

func addPlugins(group *flags.Group, name string, pluginNames []string, getter func(n string) registry.Plugin) {
	for _, n := range pluginNames {

		p := getter(n)

		opt := p.GetOpts()

		if opt == nil {
			continue
		}

		_, err := group.AddGroup(name+"."+p.GetName(), "", opt)

		if err != nil {
			panic(err)
		}
	}
}

func populateFromConfig(ini *flags.IniParser, data interface{}, longopt string) error {

	parser := flags.NewParser(data, flags.IgnoreUnknown)
	_, _ = parser.Parse()

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
	parser.LongDescription = "SSH Piper works as a proxy-like ware, and route connections by username, src ip , etc. Please see <https://github.com/tg123/sshpiper> for more information"

	// public config
	configFile := &struct {
		ConfigFile flags.Filename `long:"config" description:"Config file path. Will be overwritten by arg options and environment variables" default:"/etc/sshpiperd.ini" env:"SSHPIPERD_CONFIG_FILE" no-ini:"true"`
	}{}
	addOpt(parser.Group, "sshpiperd", configFile)

	loadFromConfigFile := func(c *flags.Command) {
		parser := flags.NewNamedParser("sshpiperd", flags.IgnoreUnknown)
		parser.Command = c
		ini := flags.NewIniParser(parser)
		ini.ParseAsDefaults = true
		err := populateFromConfig(ini, configFile, "config")
		if err != nil {
			fmt.Printf("load config file failed %v", err)
			os.Exit(1)
		}
	}

	// version
	{
		addSubCommand(parser.Command, "version", "Show version", &subCommand{func(args []string) error {
			showVersion()
			return nil
		}})
	}

	// manpage
	addSubCommand(parser.Command, "manpage", "Write man page to stdout", &subCommand{func(args []string) error {
		parser.WriteManPage(os.Stdout)
		return nil
	}})

	// plugins
	addSubCommand(parser.Command, "plugins", "List support plugins, e.g. sshpiperd plugins upstream", &subCommand{func(args []string) error {

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
	}})

	// generate key tools
	{
		addSubCommand(parser.Command, "genkey", "generate a 2048 rsa key to stdout", &subCommand{func(args []string) error {
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
		}})
	}

	// pipe management
	{
		config := &struct {
			UpstreamDriver string `long:"upstream-driver" description:"Upstream provider driver" default:"workingdir" env:"SSHPIPERD_UPSTREAM_DRIVER" ini-name:"upstream-driver"`
		}{}

		var c *flags.Command
		c = addSubCommand(parser.Command, "pipe", "manage pipe on current upstream driver", createPipeMgr(func() (upstream.Provider, error) {

			loadFromConfigFile(c)

			if config.UpstreamDriver == "" {
				return nil, fmt.Errorf("must provider upstream driver")
			}

			provider := upstream.Get(config.UpstreamDriver)
			err := provider.Init(log.New(ioutil.Discard, "", 0))
			if err != nil {
				return nil, err
			}

			return provider, nil
		}))

		addOpt(c.Group, "sshpiperd", config)
		addPlugins(c.Group, "upstream", upstream.All(), func(n string) registry.Plugin { return upstream.Get(n) })
	}

	// daemon command
	{
		config := &struct {
			piperdConfig
			loggerConfig
		}{}

		var c *flags.Command
		c = addSubCommand(parser.Command, "daemon", "run in daemon mode, serving traffic", &subCommand{func(args []string) error {
			// populate by config
			loadFromConfigFile(c)

			showVersion()

			// dump used configure only
			{
				fmt.Println()
				for _, gk := range []string{"sshpiperd", "upstream." + config.UpstreamDriver, "challenger." + config.ChallengerDriver, "auditor." + config.AuditorDriver} {

					g := c.Group.Find(gk)
					if g == nil {
						continue
					}

					fmt.Println("[" + g.ShortDescription + "]")
					for _, o := range g.Options() {
						fmt.Printf("%v = %v", o.LongName, o.Value())
						fmt.Println()
					}
					fmt.Println()
				}
			}

			return startPiper(&config.piperdConfig, config.createLogger())
		}})
		c.SubcommandsOptional = true

		addOpt(c.Group, "sshpiperd", config)
		addPlugins(c.Group, "upstream", upstream.All(), func(n string) registry.Plugin { return upstream.Get(n) })
		addPlugins(c.Group, "challenger", challenger.All(), func(n string) registry.Plugin { return challenger.Get(n) })
		addPlugins(c.Group, "auditor", auditor.All(), func(n string) registry.Plugin { return auditor.Get(n) })

		// dumpini for daemon
		addSubCommand(c, "dumpconfig", "dump current config for daemon ini to stdout", &subCommand{func(args []string) error {
			loadFromConfigFile(c)

			parser := flags.NewNamedParser("sshpiperd", flags.Default)
			parser.Command = c
			ini := flags.NewIniParser(parser)
			ini.Write(os.Stdout, flags.IniIncludeDefaults)
			return nil
		}})

		// options, for snap only at the moment
		addSubCommand(c, "options", "list all options for daemon mode", &subCommand{func(args []string) error {
			var printOpts func(*flags.Group)

			printOpts = func(group *flags.Group) {
				for _, o := range group.Options() {
					fmt.Println(o.LongName)
				}

				for _, g := range group.Groups() {
					printOpts(g)
				}
			}

			printOpts(c.Group)
			return nil
		}})
	}

	_, err := parser.Parse()
	if err != nil {
		os.Exit(1)
	}
}
