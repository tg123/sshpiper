package registry

import (
	"log"
	"reflect"
	"testing"
)

type testplugin struct {
	name string
}

func (p *testplugin) GetName() string {
	return p.name
}

func (p *testplugin) GetOpts() interface{} {
	return nil
}

func (p *testplugin) Init(logger *log.Logger) error {
	return nil
}

func TestRegistry_Register(t *testing.T) {
	r := NewRegistry()

	r.Register("x", &testplugin{"x"})
	r.Register("y", &testplugin{"y"})

	if r.Get("x") == nil {
		t.Errorf("cannot find x in registry")
	}

	all := r.Drivers()

	if !reflect.DeepEqual(all, []string{"x", "y"}) {
		t.Errorf("should contain x y in registry")
	}

	if r.Get("z") != nil {
		t.Errorf("should not find z in registry")
	}

	// duplicate name
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("should panic")
			}
		}()

		r := NewRegistry()
		r.Register("x", &testplugin{"x"})
		r.Register("x", &testplugin{"x"})

	}()

	// nil driver
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("should panic")
			}
		}()

		r := NewRegistry()
		r.Register("nil", nil)
	}()
}
