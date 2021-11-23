package pome

import (
	"github.com/tg123/sshpiper/sshpiperd/challenger"
	"github.com/tg123/sshpiper/sshpiperd/upstream"
	"log"
)

type plugin struct {
	pome
}

func (plugin) GetName() string {
	return "pome"
}

func (plugin) GetOpts() interface{} {
	return nil
}

func (p *plugin) Init(logger *log.Logger) error {
	p.pome.logger = logger
	return nil
}

func (plugin) ListPipe() ([]upstream.Pipe, error) {
	return nil, nil
}

func (plugin) CreatePipe(opt upstream.CreatePipeOption) error {
	return nil
}

func (plugin) RemovePipe(name string) error {
	return nil
}

type challengerPlugin struct {
	*plugin
}

func (p *challengerPlugin) GetHandler() challenger.Handler {
	return p.challenge
}

type upstreamPlugin struct {
	*plugin
}

func (p *upstreamPlugin) GetHandler() upstream.Handler {
	return p.authWithPipe
}

func (p *challengerPlugin) GetOpts() interface{} {
	return &p.Config
}

func init() {
	p := &plugin{}
	upstream.Register("pome", &upstreamPlugin{p})
	challenger.Register("pome", &challengerPlugin{p})
}
