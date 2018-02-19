package challenger

import (
	"log"
)

type plugin struct {
	name    string
	init    func(logger *log.Logger) error
	opts    interface{}
	handler ChallengerHandler
}

func (p *plugin) GetName() string {
	return p.name
}

func (p *plugin) GetOpts() interface{} {
	return p.opts
}

func (p *plugin) GetChallengerHandler() ChallengerHandler {
	return p.handler
}

func (p *plugin) Init(logger *log.Logger) error {
	logger.Printf("challenger: %v init", p.name)

	if p.init != nil {
		return p.init(logger)
	}
	return nil
}

func NewFromHandler(name string, handler ChallengerHandler, opts interface{}, init func(glogger *log.Logger) error) Challenger {
	return &plugin{
		name:    name,
		init:    init,
		opts:    opts,
		handler: handler,
	}
}
