package registry

import (
	"sort"
	"sync"
)

// Registry is a place to hold all plugins
type Registry struct {
	driversMu sync.RWMutex
	drivers   map[string]interface{}
}

// NewRegistry creates a new Registry
func NewRegistry() *Registry {
	return &Registry{drivers: make(map[string]interface{})}
}

// Register adds a Plugin with given name to Registry
func (r *Registry) Register(name string, driver interface{}) {
	// copy from database/sql
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

// Drivers return all registered Plugins
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

// Get returns an Plugins by name, return nil if not found
func (r *Registry) Get(name string) interface{} {
	r.driversMu.RLock()
	defer r.driversMu.RUnlock()

	return r.drivers[name]
}
