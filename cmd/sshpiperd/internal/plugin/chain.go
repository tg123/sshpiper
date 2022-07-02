package plugin

import (
	"fmt"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

type ChainPlugins struct {
	pluginsCallback []*ssh.PiperConfig
	plugins         []*GrpcPlugin
}

func (cp *ChainPlugins) Append(p *GrpcPlugin) error {
	config, err := p.CreatePiperConfig()
	if err != nil {
		return err
	}

	p.OnNextPlugin = cp.onNextPlugin
	cp.pluginsCallback = append(cp.pluginsCallback, config)
	cp.plugins = append(cp.plugins, p)

	return nil
}

func (cp *ChainPlugins) onNextPlugin(challengeCtx ssh.ChallengeContext, upstream *libplugin.UpstreamNextPluginAuth) error {
	chain := challengeCtx.(*chainConnMeta)

	if chain.current+1 >= len(cp.pluginsCallback) {
		return fmt.Errorf("no more plugins")
	}

	chain.current++
	return nil
}

type chainConnMeta struct {
	connMeta
	current int
}

func (cp *ChainPlugins) CreateChallengeContext(conn ssh.ConnMetadata) (ssh.ChallengeContext, error) {
	uiq, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	meta := chainConnMeta{
		connMeta: connMeta{
			UserName: conn.User(),
			FromAddr: conn.RemoteAddr().String(),
			UniqId:   uiq.String(),
		},
	}

	for _, p := range cp.plugins {
		if err := p.NewConnection(&meta.connMeta); err != nil {
			return nil, err
		}
	}

	return &meta, nil
}

func (cp *ChainPlugins) NextAuthMethods(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) ([]string, error) {
	chain := challengeCtx.(*chainConnMeta)
	config := cp.pluginsCallback[chain.current]

	if config.NextAuthMethods != nil {
		return config.NextAuthMethods(conn, challengeCtx)
	}

	var methods []string

	if config.NoneAuthCallback != nil {
		methods = append(methods, "none")
	}

	if config.PasswordCallback != nil {
		methods = append(methods, "password")
	}

	if config.PublicKeyCallback != nil {
		methods = append(methods, "publickey")
	}

	if config.KeyboardInteractiveCallback != nil {
		methods = append(methods, "keyboard-interactive")
	}

	log.Debugf("next auth methods %v", methods)
	return methods, nil
}

func (cp *ChainPlugins) InstallPiperConfig(config *ssh.PiperConfig) error {

	config.CreateChallengeContext = func(conn ssh.ConnMetadata) (ssh.ChallengeContext, error) {
		ctx, err := cp.CreateChallengeContext(conn)
		if err != nil {
			log.Errorf("cannot create challenge context %v", err)
		}
		return ctx, err
	}

	config.NextAuthMethods = cp.NextAuthMethods

	config.NoneAuthCallback = func(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
		return cp.pluginsCallback[challengeCtx.(*chainConnMeta).current].NoneAuthCallback(conn, challengeCtx)
	}

	config.PasswordCallback = func(conn ssh.ConnMetadata, password []byte, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
		return cp.pluginsCallback[challengeCtx.(*chainConnMeta).current].PasswordCallback(conn, password, challengeCtx)
	}

	config.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
		return cp.pluginsCallback[challengeCtx.(*chainConnMeta).current].PublicKeyCallback(conn, key, challengeCtx)
	}

	config.KeyboardInteractiveCallback = func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
		return cp.pluginsCallback[challengeCtx.(*chainConnMeta).current].KeyboardInteractiveCallback(conn, client, challengeCtx)
	}

	config.UpstreamAuthFailureCallback = func(conn ssh.ConnMetadata, method string, err error, challengeCtx ssh.ChallengeContext) {
		cur := cp.pluginsCallback[challengeCtx.(*chainConnMeta).current]
		if cur.UpstreamAuthFailureCallback != nil {
			cur.UpstreamAuthFailureCallback(conn, method, err, challengeCtx)
		}
	}

	config.BannerCallback = func(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) string {
		cur := cp.pluginsCallback[challengeCtx.(*chainConnMeta).current]
		if cur.BannerCallback != nil {
			return cur.BannerCallback(conn, challengeCtx)
		}

		return ""
	}

	return nil
}
