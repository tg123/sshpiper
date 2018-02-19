package main

import (
	"fmt"
	"os"

	"github.com/jessevdk/go-flags"

	"github.com/tg123/sshpiper/sshpiperd/auditor"
	_ "github.com/tg123/sshpiper/sshpiperd/auditor/loader"
	"github.com/tg123/sshpiper/sshpiperd/challenger"
	_ "github.com/tg123/sshpiper/sshpiperd/challenger/loader"
	"github.com/tg123/sshpiper/sshpiperd/registry"
	"github.com/tg123/sshpiper/sshpiperd/upstream"
	_ "github.com/tg123/sshpiper/sshpiperd/upstream/loader"
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

func main() {

	parser := flags.NewNamedParser("sshpiperd", flags.Default)
	parser.SubcommandsOptional = true

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

	config := &struct {
		piperdConfig

		Logfile    string         `long:"log" description:"Logfile path. Leave empty or any error occurs will fall back to stdout" env:"SSHPIPERD_LOG_PATH" ini-name:"log-path"`
		ConfigFile flags.Filename `long:"config" description:"Config file path. Higher priority than arg options and environment variables" default:"/etc/sshpiperd.ini" no-ini:"true"`
	}{}

	addOpt(parser, "sshpiperd", config)

	addPlugins(parser, "upstream", upstream.All(), func(n string) registry.Plugin { return upstream.Get(n) })
	addPlugins(parser, "challenger", challenger.All(), func(n string) registry.Plugin { return challenger.Get(n) })
	addPlugins(parser, "auditor", auditor.All(), func(n string) registry.Plugin { return auditor.Get(n) })

	if _, err := parser.Parse(); err != nil {
		return
	}

	o := parser.FindOptionByLongName("config")
	ini := flags.NewIniParser(parser)
	err := ini.ParseFile(string(config.ConfigFile))

	if err != nil {
		// set by user
		if !o.IsSetDefault() {
			fmt.Printf("load config file %v failed %v", config.ConfigFile, err)
			fmt.Println()
			os.Exit(1)
		}
	}

	// init log
	initLogger(config.Logfile)

	// no subcommand called, start to serve
	if parser.Active == nil {
		showVersion()
		dumpConfig()

		startPiper(&config.piperdConfig)
	}

}
