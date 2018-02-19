package registry

import (
	"log"
)

type Plugin interface {
	GetName() string

	GetOpts() interface{}

	Init(logger *log.Logger) error
}
