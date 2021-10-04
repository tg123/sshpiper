package main

import (
	"log"
	"testing"

	"fmt"
	"github.com/tg123/sshpiper/sshpiperd/auditor"
	"github.com/tg123/sshpiper/sshpiperd/challenger"
	"github.com/tg123/sshpiper/sshpiperd/registry"
	"github.com/tg123/sshpiper/sshpiperd/upstream"
	"golang.org/x/crypto/ssh"
	"net"
	"time"
)

type testplugin struct {
	name string
	init func(logger *log.Logger) error
}

func (p *testplugin) GetName() string {
	return p.name
}

func (p *testplugin) GetOpts() interface{} {
	return nil
}

func (p *testplugin) Init(logger *log.Logger) error {
	if p.init == nil {
		return nil
	}
	return p.init(logger)
}

func Test_getAndInstall(t *testing.T) {
	var err error

	// ignore empty
	_ = getAndInstall("", "", func(n string) registry.Plugin {
		t.Errorf("should not call get")
		return nil
	}, func(plugin registry.Plugin) error {
		t.Errorf("should not call install")
		return nil
	}, nil)

	// fail when not found
	err = getAndInstall("", "test", func(n string) registry.Plugin {
		if n != "test" {
			t.Errorf("plugin name changed")
		}
		return nil
	}, func(plugin registry.Plugin) error {
		t.Errorf("should not call install")
		return nil
	}, nil)

	if err == nil {
		t.Errorf("should err when not found")
	}

	// init err
	err = getAndInstall("", "test", func(n string) registry.Plugin {
		return &testplugin{
			init: func(logger *log.Logger) error {
				return fmt.Errorf("init failed")
			},
		}
	}, func(plugin registry.Plugin) error {
		return fmt.Errorf("test")
	}, nil)

	if err == nil {
		t.Errorf("should err when not found")
	}

	// call init
	inited := false
	installed := false
	err = getAndInstall("", "test", func(n string) registry.Plugin {
		if n != "test" {
			t.Errorf("plugin name changed")
		}
		return &testplugin{
			init: func(logger *log.Logger) error {
				inited = true
				return nil
			},
		}
	}, func(plugin registry.Plugin) error {
		if !inited {
			t.Errorf("not inited")
		}

		installed = true
		return nil
	}, nil)

	if !installed {
		t.Errorf("not installed")
	}

	if err != nil {
		t.Errorf("should err when not found")
	}
}

type testupstream struct {
	testplugin

	h upstream.Handler
}

func (t *testupstream) ListPipe() ([]upstream.Pipe, error) {
	return nil, nil
}

func (t *testupstream) CreatePipe(opt upstream.CreatePipeOption) error {
	return nil
}

func (t *testupstream) RemovePipe(name string) error {
	return nil
}

func (t *testupstream) GetHandler() upstream.Handler {
	return t.h
}

type testchallenger struct {
	testplugin

	h challenger.Handler
}

func (t *testchallenger) GetHandler() challenger.Handler {
	return t.h
}

type testauditorprovider struct {
	testplugin

	a auditor.Auditor
}

func (t *testauditorprovider) Create(ssh.ConnMetadata) (auditor.Auditor, error) {
	return t.a, nil
}

type testauditor struct {
	up   auditor.Hook
	down auditor.Hook
}

func (t *testauditor) GetUpstreamHook() auditor.Hook {
	return t.up
}

func (t *testauditor) GetDownstreamHook() auditor.Hook {
	return t.down
}

func (t *testauditor) Close() error {
	return nil
}

func Test_installDriver(t *testing.T) {
	var (
		upstreamName    = fmt.Sprintf("u_%v", time.Now().UTC().UnixNano())
		challengerName  = fmt.Sprintf("c_%v", time.Now().UTC().UnixNano())
		auditorName     = fmt.Sprintf("a_%v", time.Now().UTC().UnixNano())
		upstreamErrName = fmt.Sprintf("ue_%v", time.Now().UTC().UnixNano())
		upstreamNilName = fmt.Sprintf("un_%v", time.Now().UTC().UnixNano())
	)

	findUpstream := func(conn ssh.ConnMetadata, challengeContext ssh.AdditionalChallengeContext) (net.Conn, *ssh.AuthPipe, error) {
		return nil, nil, nil
	}

	upstream.Register(upstreamName, &testupstream{
		testplugin: testplugin{
			name: upstreamName,
		},
		h: findUpstream,
	})

	upstream.Register(upstreamErrName, &testupstream{
		testplugin: testplugin{
			name: upstreamErrName,
			init: func(logger *log.Logger) error {
				return fmt.Errorf("test err")
			},
		},
		h: findUpstream,
	})

	upstream.Register(upstreamNilName, &testupstream{
		testplugin: testplugin{
			name: upstreamNilName,
		},
		h: nil,
	})

	challenger.Register(challengerName, &testchallenger{
		testplugin: testplugin{
			name: upstreamName,
		},
		h: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (ssh.AdditionalChallengeContext, error) {
			return nil, nil
		},
	})

	auditor.Register(auditorName, &testauditorprovider{})

	// empty driver name
	{
		piper := &ssh.PiperConfig{}
		_, err := installDrivers(piper, &piperdConfig{
			UpstreamDriver: "",
		}, nil)

		if err == nil {
			t.Errorf("should fail when empty driver")
		}
	}

	// install upstream
	{
		piper := &ssh.PiperConfig{}
		_, err := installDrivers(piper, &piperdConfig{
			UpstreamDriver: upstreamName,
		}, nil)

		if err != nil {
			t.Errorf("install failed %v", err)
		}

		if _, _, err := piper.FindUpstream(nil, nil); err != nil {
			t.Errorf("install wrong func")
		}

		if piper.AdditionalChallenge != nil {
			t.Errorf("should not install challenger")
		}
	}

	// install upstream with failed init
	{
		piper := &ssh.PiperConfig{}
		_, err := installDrivers(piper, &piperdConfig{
			UpstreamDriver: upstreamErrName,
		}, nil)

		if err == nil {
			t.Errorf("install should fail")
		}

		if piper.FindUpstream != nil {
			t.Errorf("should not install upstream provider")
		}

		if piper.AdditionalChallenge != nil {
			t.Errorf("should not install challenger")
		}
	}

	// install upstream with nil handler
	{
		piper := &ssh.PiperConfig{}
		_, err := installDrivers(piper, &piperdConfig{
			UpstreamDriver: upstreamNilName,
		}, nil)

		if err == nil {
			t.Errorf("install should fail")
		}

		if piper.FindUpstream != nil {
			t.Errorf("should not install upstream provider")
		}

		if piper.AdditionalChallenge != nil {
			t.Errorf("should not install challenger")
		}
	}

	// install challenger
	{
		piper := &ssh.PiperConfig{}
		_, err := installDrivers(piper, &piperdConfig{
			UpstreamDriver:   upstreamName,
			ChallengerDriver: challengerName,
		}, nil)

		if err != nil {
			t.Errorf("install failed %v", err)
		}

		if _, err := piper.AdditionalChallenge(nil, nil); err != nil {
			t.Errorf("should install challenger")
		}
	}

	// install auditor
	{
		piper := &ssh.PiperConfig{}
		ap, err := installDrivers(piper, &piperdConfig{
			UpstreamDriver: upstreamName,
			AuditorDriver:  auditorName,
		}, nil)

		if err != nil {
			t.Errorf("install failed %v", err)
		}

		if ap == nil {
			t.Errorf("nil auditor provider")
		}

		ap0 := ap.(*testauditorprovider)

		ap0.a = &testauditor{
			up: func(conn ssh.ConnMetadata, msg []byte) ([]byte, error) {
				msg[0] = 42
				return msg, nil
			},
			down: func(conn ssh.ConnMetadata, msg []byte) ([]byte, error) {
				msg[0] = 100
				return msg, nil
			},
		}

		a, err := ap.Create(nil)
		if err != nil {
			t.Errorf("install failed %v", err)
		}

		m := []byte{0}

		if _, err := a.GetUpstreamHook()(nil, m); err != nil {
			t.Errorf("run upstream hook %v", err)
		}

		if m[0] != 42 {
			t.Errorf("upstream not handled")
		}

		if _, err := a.GetDownstreamHook()(nil, m); err != nil {
			t.Errorf("run downstream hook %v", err)
		}
		if m[0] != 100 {
			t.Errorf("downstream not handled")
		}
	}
}
