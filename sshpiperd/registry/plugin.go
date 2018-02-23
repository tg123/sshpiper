package registry

import (
	"log"
)

// Plugin is to be registered with sshpiper to provide additional functions
type Plugin interface {

	// The name of the Plugin
	GetName() string

	// A ref to a struct which holds the options for the plugins
	// will be populated by cmd or other plugin runners
	GetOpts() interface{}

	// Will be called before the Plugin is used to ensure the Plugin is ready
	Init(logger *log.Logger) error
}
