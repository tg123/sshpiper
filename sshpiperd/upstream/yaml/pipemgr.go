package yaml

import (
	"fmt"

	"github.com/tg123/sshpiper/sshpiperd/upstream"
	"gopkg.in/yaml.v2"
)

// Return All pipes inside upstream
func (p *plugin) ListPipe() ([]upstream.Pipe, error) {

	config, err := p.loadConfig()

	if err != nil {
		return nil, err
	}

	out, err := yaml.Marshal(config)
	if err != nil {
		return nil, err
	}

	fmt.Println(string(out))

	return nil, nil
}

// Create a pipe inside upstream
func (p *plugin) CreatePipe(opt upstream.CreatePipeOption) error {
	panic("not implemented") // TODO: Implement
}

// Remove a pipe from upstream
func (p *plugin) RemovePipe(name string) error {
	panic("not implemented") // TODO: Implement
}
