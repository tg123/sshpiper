package registry

import (
	"sort"
	"sync"
)

type Registry struct {
	driversMu sync.RWMutex
	drivers   map[string]interface{}
}

func NewRegistry() *Registry {
	return &Registry{drivers: make(map[string]interface{})}
}

// copy from database/sql
func (r *Registry) Register(name string, driver interface{}) {
	r.driversMu.Lock()
	defer r.driversMu.Unlock()
	if driver == nil {
		panic("Register driver is nil")
	}
	if _, dup := r.drivers[name]; dup {
		panic("Register called twice for driver " + name)
	}
	r.drivers[name] = driver
}

func (r *Registry) Drivers() []string {
	r.driversMu.RLock()
	defer r.driversMu.RUnlock()
	var list []string
	for name := range r.drivers {
		list = append(list, name)
	}
	sort.Strings(list)
	return list
}

func (r *Registry) Get(name string) interface{} {
	r.driversMu.RLock()
	defer r.driversMu.RUnlock()

	return r.drivers[name]
}
