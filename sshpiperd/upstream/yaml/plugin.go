package yaml

import (
	"log"

	"github.com/tg123/sshpiper/sshpiperd/upstream"
)

type plugin struct {
	Config struct {
		File        string `long:"upstream-yaml-file" default:"/var/sshpiper/sshpiperd.yaml" description:"Yaml config file path" env:"SSHPIPERD_UPSTREAM_YAML_FILE" ini-name:"upstream-yaml-file"`
		NoCheckPerm bool   `long:"upstream-yaml-nocheckperm" description:"Disable 0400 checking when using config file" env:"SSHPIPERD_UPSTREAM_YAML_NOCHECKPERM" ini-name:"upstream-yaml-nocheckperm"`
	}

	logger *log.Logger
}

// The name of the Plugin
func (p *plugin) GetName() string {
	return "yaml"
}

// A ref to a struct which holds the options for the plugins
// will be populated by cmd or other plugin runners
func (p *plugin) GetOpts() interface{} {
	return &p.Config
}

// Will be called before the Plugin is used to ensure the Plugin is ready
func (p *plugin) Init(logger *log.Logger) error {
	p.logger = logger
	return nil
}

func (p *plugin) GetHandler() upstream.Handler {
	return p.findUpstream
}

func init() {
	upstream.Register("yaml", &plugin{})
}
