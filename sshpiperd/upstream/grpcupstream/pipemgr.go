package grpcupstream

import (
	"github.com/tg123/sshpiper/sshpiperd/upstream"
)

// Return All pipes inside upstream
func (p *plugin) ListPipe() ([]upstream.Pipe, error) {
	return nil, nil
}

// Create a pipe inside upstream
func (p *plugin) CreatePipe(opt upstream.CreatePipeOption) error {
	return nil
}

// Remove a pipe from upstream
func (p *plugin) RemovePipe(name string) error {
	return nil
}
