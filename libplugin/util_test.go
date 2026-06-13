package libplugin

import (
	"io"
	"testing"
)

func TestChainedConfigLogger(t *testing.T) {
	var called []string

	first := func(w io.Writer, level string, tty bool) {
		called = append(called, "first:"+level)
	}
	second := func(w io.Writer, level string, tty bool) {
		if !tty {
			t.Fatalf("expected tty=true")
		}
		called = append(called, "second")
	}

	chained := ChainedConfigLogger(first, nil, second)
	chained(io.Discard, "debug", true)

	if len(called) != 2 || called[0] != "first:debug" || called[1] != "second" {
		t.Fatalf("unexpected calls: %#v", called)
	}
}
