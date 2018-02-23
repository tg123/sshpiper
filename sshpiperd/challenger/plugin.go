package challenger

import (
	"log"
)

type plugin struct {
	name       string
	init       func(logger *log.Logger) error
	opts       interface{}
	gethandler func() Handler
}

func (p *plugin) GetName() string {
	return p.name
}

func (p *plugin) GetOpts() interface{} {
	return p.opts
}

func (p *plugin) GetHandler() Handler {
	return p.gethandler()
}

func (p *plugin) Init(logger *log.Logger) error {
	logger.Printf("challenger: %v init", p.name)

	if p.init != nil {
		return p.init(logger)
	}
	return nil
}

// NewFromHandler creates a Challenger with given functions
func NewFromHandler(name string, gethandler func() Handler, opts interface{}, init func(glogger *log.Logger) error) Provider {
	return &plugin{
		name:       name,
		init:       init,
		opts:       opts,
		gethandler: gethandler,
	}
}
