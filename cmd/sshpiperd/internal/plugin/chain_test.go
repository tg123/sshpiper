package plugin

import (
	"net"
	"reflect"
	"testing"

	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

type mockAddr string

func (a mockAddr) Network() string { return "tcp" }
func (a mockAddr) String() string  { return string(a) }

type mockConnMetadata struct {
	user       string
	remoteAddr net.Addr
	localAddr  net.Addr
}

func (m mockConnMetadata) User() string          { return m.user }
func (m mockConnMetadata) SessionID() []byte     { return []byte("session") }
func (m mockConnMetadata) ClientVersion() []byte { return []byte("client") }
func (m mockConnMetadata) ServerVersion() []byte { return []byte("server") }
func (m mockConnMetadata) RemoteAddr() net.Addr  { return m.remoteAddr }
func (m mockConnMetadata) LocalAddr() net.Addr   { return m.localAddr }

func TestChainPluginsOnNextPlugin(t *testing.T) {
	cp := &ChainPlugins{
		pluginsCallback: []*GrpcPluginConfig{{}, {}},
	}

	ctx := &chainConnMeta{
		PluginConnMeta: PluginConnMeta{
			Metadata: map[string]string{"existing": "value"},
		},
		current: 0,
	}

	upstream := &libplugin.UpstreamNextPluginAuth{
		Meta: map[string]string{"new": "meta"},
	}

	if err := cp.onNextPlugin(ctx, upstream); err != nil {
		t.Fatalf("onNextPlugin returned error: %v", err)
	}

	if ctx.current != 1 {
		t.Fatalf("expected current to advance to 1, got %d", ctx.current)
	}

	if ctx.Metadata["existing"] != "value" || ctx.Metadata["new"] != "meta" {
		t.Fatalf("metadata not merged correctly: %+v", ctx.Metadata)
	}
}

func TestChainPluginsOnNextPluginNoMore(t *testing.T) {
	cp := &ChainPlugins{
		pluginsCallback: []*GrpcPluginConfig{{}},
	}

	ctx := &chainConnMeta{}
	if err := cp.onNextPlugin(ctx, &libplugin.UpstreamNextPluginAuth{}); err == nil {
		t.Fatalf("expected error when no more plugins")
	}
}

func TestChainPluginsNextAuthMethodsDefault(t *testing.T) {
	config := &GrpcPluginConfig{
		PiperConfig: ssh.PiperConfig{
			NoClientAuthCallback: func(ssh.ConnMetadata, ssh.ChallengeContext) (*ssh.Upstream, error) { return nil, nil },
			PasswordCallback:     func(ssh.ConnMetadata, []byte, ssh.ChallengeContext) (*ssh.Upstream, error) { return nil, nil },
			PublicKeyCallback:    func(ssh.ConnMetadata, ssh.PublicKey, ssh.ChallengeContext) (*ssh.Upstream, error) { return nil, nil },
			KeyboardInteractiveCallback: func(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge, ssh.ChallengeContext) (*ssh.Upstream, error) {
				return nil, nil
			},
		},
	}

	cp := &ChainPlugins{
		pluginsCallback: []*GrpcPluginConfig{config},
	}

	ctx := &chainConnMeta{}
	conn := mockConnMetadata{
		user:       "user",
		remoteAddr: mockAddr("remote:22"),
		localAddr:  mockAddr("local:22"),
	}

	methods, err := cp.NextAuthMethods(conn, ctx)
	if err != nil {
		t.Fatalf("NextAuthMethods returned error: %v", err)
	}

	expected := []string{"none", "password", "publickey", "keyboard-interactive"}
	if !reflect.DeepEqual(methods, expected) {
		t.Fatalf("expected %v, got %v", expected, methods)
	}
}

func TestChainPluginsNextAuthMethodsCustom(t *testing.T) {
	config := &GrpcPluginConfig{
		PiperConfig: ssh.PiperConfig{
			NextAuthMethods: func(ssh.ConnMetadata, ssh.ChallengeContext) ([]string, error) {
				return []string{"custom"}, nil
			},
		},
	}

	cp := &ChainPlugins{
		pluginsCallback: []*GrpcPluginConfig{config},
	}

	methods, err := cp.NextAuthMethods(mockConnMetadata{}, &chainConnMeta{})
	if err != nil {
		t.Fatalf("NextAuthMethods returned error: %v", err)
	}

	expected := []string{"custom"}
	if !reflect.DeepEqual(methods, expected) {
		t.Fatalf("expected %v, got %v", expected, methods)
	}
}

func TestChainPluginsInstallPiperConfigUsesCurrentPlugin(t *testing.T) {
	firstUpstream := &ssh.Upstream{}
	secondUpstream := &ssh.Upstream{}

	var firstCalled, secondCalled bool

	cp := &ChainPlugins{
		pluginsCallback: []*GrpcPluginConfig{
			{
				PiperConfig: ssh.PiperConfig{
					NoClientAuthCallback: func(ssh.ConnMetadata, ssh.ChallengeContext) (*ssh.Upstream, error) {
						firstCalled = true
						return firstUpstream, nil
					},
				},
			},
			{
				PiperConfig: ssh.PiperConfig{
					NoClientAuthCallback: func(ssh.ConnMetadata, ssh.ChallengeContext) (*ssh.Upstream, error) {
						secondCalled = true
						return secondUpstream, nil
					},
				},
			},
		},
	}

	config := &GrpcPluginConfig{}
	if err := cp.InstallPiperConfig(config); err != nil {
		t.Fatalf("InstallPiperConfig returned error: %v", err)
	}

	conn := mockConnMetadata{
		user:       "user",
		remoteAddr: mockAddr("remote:22"),
		localAddr:  mockAddr("local:22"),
	}

	ctx := &chainConnMeta{}
	up, err := config.NoClientAuthCallback(conn, ctx)
	if err != nil {
		t.Fatalf("NoClientAuthCallback returned error: %v", err)
	}
	if up != firstUpstream || !firstCalled {
		t.Fatalf("expected first plugin callback to be used")
	}

	ctx.current = 1
	up, err = config.NoClientAuthCallback(conn, ctx)
	if err != nil {
		t.Fatalf("NoClientAuthCallback returned error: %v", err)
	}
	if up != secondUpstream || !secondCalled {
		t.Fatalf("expected second plugin callback to be used")
	}
}
