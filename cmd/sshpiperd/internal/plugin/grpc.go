package plugin

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/remotesigner"
	"github.com/tg123/remotesigner/grpcsigner"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/libplugin/ioconn"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type GrpcPlugin struct {
	Name         string
	OnNextPlugin func(conn ssh.ChallengeContext, upstream *libplugin.UpstreamNextPluginAuth) error

	grpcconn           *grpc.ClientConn
	client             libplugin.SshPiperPluginClient
	remotesignerClient grpcsigner.SignerClient

	hasNewConnectionCallback bool
	allowedMethod            map[string]bool
}

func DialGrpc(conn *grpc.ClientConn) (*GrpcPlugin, error) {
	p := &GrpcPlugin{
		grpcconn:           conn,
		client:             libplugin.NewSshPiperPluginClient(conn),
		remotesignerClient: grpcsigner.NewSignerClient(conn),
	}

	return p, nil
}

func (g *GrpcPlugin) InstallPiperConfig(config *ssh.PiperConfig) error {

	cb, err := g.client.ListCallbacks(context.Background(), &libplugin.ListCallbackRequest{})
	if err != nil {
		return err
	}

	// config.NextAuthMethods = g.NextAuthMethodsLocal
	// config.UpstreamAuthFailureCallback = g.UpstreamAuthFailureCallbackLocal

	config.CreateChallengeContext = func(conn ssh.ConnMetadata) (ssh.ChallengeContext, error) {
		ctx, err := g.CreateChallengeContext(conn)
		if err != nil {
			log.Errorf("cannot create challenge context %v", err)
		}
		return ctx, err
	}

	for _, c := range cb.Callbacks {
		switch c {
		case "NewConnection":
			g.hasNewConnectionCallback = true
		case "NextAuthMethods":
			config.NextAuthMethods = func(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) ([]string, error) {
				methods, err := g.NextAuthMethodsRemote(conn, challengeCtx)
				if err != nil {
					log.Errorf("cannot get next auth methods %v", err)
				}

				log.Debugf("next auth methods %v", methods)
				return methods, err
			}

		case "NoneAuth":
			config.NoneAuthCallback = func(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
				log.Debugf("downstream %v is sending none auth", conn.RemoteAddr().String())
				u, err := g.NoneAuthCallback(conn, challengeCtx)
				if err != nil {
					log.Errorf("cannot create upstream for %v with none auth: %v", conn.RemoteAddr().String(), err)
				}
				return u, err
			}
		case "PasswordAuth":
			config.PasswordCallback = func(conn ssh.ConnMetadata, password []byte, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
				log.Debugf("downstream %v is sending password auth", conn.RemoteAddr().String())
				u, err := g.PasswordCallback(conn, password, challengeCtx)
				if err != nil {
					log.Errorf("cannot create upstream for %v with password auth: %v", conn.RemoteAddr().String(), err)
				}
				return u, err
			}
		case "PublicKeyAuth":
			config.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
				log.Debugf("downstream %v is sending public key auth", conn.RemoteAddr().String())
				u, err := g.PublicKeyCallback(conn, key, challengeCtx)
				if err != nil {
					log.Errorf("cannot create upstream for %v with public key auth: %v", conn.RemoteAddr().String(), err)
				}
				return u, err
			}
		case "KeyboardInteractiveAuth":
			config.KeyboardInteractiveCallback = func(conn ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
				log.Debugf("downstream %v is sending keyboard interactive auth", conn.RemoteAddr().String())
				u, err := g.KeyboardInteractiveCallback(conn, challenge, challengeCtx)
				if err != nil {
					log.Errorf("cannot create upstream for %v with keyboard interactive auth: %v", conn.RemoteAddr().String(), err)
				}
				return u, err
			}
		case "UpstreamAuthFailure":
			config.UpstreamAuthFailureCallback = func(conn ssh.ConnMetadata, method string, err error, challengeCtx ssh.ChallengeContext) {
				log.Debugf("upstream rejected [%v] auth: %v", method, err)
				g.UpstreamAuthFailureCallbackRemote(conn, method, err, challengeCtx)
			}
		case "Banner":
			config.BannerCallback = g.BannerCallback
		case "VerifyHostKey":
			// ignore
		default:
			return fmt.Errorf("unknown callback %s", c)
		}
	}

	return nil
}

func (g *GrpcPlugin) CreatePiperConfig() (*ssh.PiperConfig, error) {
	config := &ssh.PiperConfig{}
	return config, g.InstallPiperConfig(config)
}

type connMeta libplugin.ConnMeta

// ChallengedUsername implements ssh.ChallengeContext
func (m *connMeta) ChallengedUsername() string {
	return m.UserName
}

// Meta implements ssh.ChallengeContext
func (m *connMeta) Meta() interface{} {
	return m
}

func (g *GrpcPlugin) CreateChallengeContext(conn ssh.ConnMetadata) (ssh.ChallengeContext, error) {
	uiq, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	meta := connMeta{
		UserName: conn.User(),
		FromAddr: conn.RemoteAddr().String(),
		UniqId:   uiq.String(),
	}

	return &meta, g.NewConnection(&meta)
}

func (g *GrpcPlugin) NewConnection(meta *connMeta) error {
	if g.hasNewConnectionCallback {
		_, err := g.client.NewConnection(context.Background(), &libplugin.NewConnectionRequest{
			Meta: &libplugin.ConnMeta{
				UserName: meta.UserName,
				FromAddr: meta.FromAddr,
				UniqId:   meta.UniqId,
			},
		})

		return err
	}

	return nil
}

func (g *GrpcPlugin) NextAuthMethodsLocal(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) ([]string, error) {
	var allow []string

	for k, v := range g.allowedMethod {
		if v {
			allow = append(allow, k)
		}
	}

	return allow, nil
}

func toMeta(challengeCtx ssh.ChallengeContext, conn ssh.ConnMetadata) *libplugin.ConnMeta {
	switch meta := challengeCtx.(type) {
	case *connMeta:
		meta.UserName = conn.User()
		return (*libplugin.ConnMeta)(meta)
	case *chainConnMeta:
		meta.UserName = conn.User()
		return (*libplugin.ConnMeta)(&meta.connMeta)
	}

	panic("unknown challenge context")
}

func (g *GrpcPlugin) NextAuthMethodsRemote(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) ([]string, error) {
	meta := toMeta(challengeCtx, conn)
	reply, err := g.client.NextAuthMethods(context.Background(), &libplugin.NextAuthMethodsRequest{
		Meta: meta,
	})

	if err != nil {
		return nil, err
	}

	var methods []string

	for _, method := range reply.Methods {
		m := libplugin.AuthMethodTypeToName(method)
		if m == "" {
			continue
		}
		methods = append(methods, m)
	}

	return methods, nil
}

func (g *GrpcPlugin) UpstreamAuthFailureCallbackLocal(onn ssh.ConnMetadata, method string, err error, challengeCtx ssh.ChallengeContext) {
	noMoreMethodErr, ok := err.(ssh.NoMoreMethodsErr)
	if ok {
		for _, allowed := range noMoreMethodErr.Allowed {
			g.allowedMethod[allowed] = true
		}

		return
	}

	g.allowedMethod[method] = false
}

func (g *GrpcPlugin) UpstreamAuthFailureCallbackRemote(conn ssh.ConnMetadata, method string, err error, challengeCtx ssh.ChallengeContext) {
	noMoreMethodErr, ok := err.(ssh.NoMoreMethodsErr)
	allowed := make([]libplugin.AuthMethod, len(noMoreMethodErr.Allowed))
	if ok {
		for _, method := range noMoreMethodErr.Allowed {
			m := libplugin.AuthMethodFromName(method)
			if m == -1 {
				continue
			}

			allowed = append(allowed, m)
		}
	}

	_, _ = g.client.UpstreamAuthFailureNotice(context.Background(), &libplugin.UpstreamAuthFailureNoticeRequest{
		Meta:           toMeta(challengeCtx, conn),
		Method:         method,
		Error:          err.Error(),
		AllowedMethods: allowed,
	})
}

func (g *GrpcPlugin) createUpstream(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext, upstream *libplugin.Upstream) (*ssh.Upstream, error) {
	if upstream.GetNextPlugin() != nil {
		if g.OnNextPlugin == nil {
			return nil, fmt.Errorf("next plugin is not supported")
		}
		return nil, g.OnNextPlugin(challengeCtx, upstream.GetNextPlugin())
	}

	meta := toMeta(challengeCtx, conn)

	port := upstream.Port
	if port <= 0 {
		port = 22
	}
	addr := net.JoinHostPort(upstream.Host, strconv.Itoa(int(port)))

	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	config := ssh.ClientConfig{
		User: upstream.UserName,
		HostKeyCallback: func(hostname string, addr net.Addr, key ssh.PublicKey) error {
			if upstream.IgnoreHostKey {
				return nil
			}

			verify, err := g.client.VerifyHostKey(context.Background(), &libplugin.VerifyHostKeyRequest{
				Meta:       meta,
				Hostname:   hostname,
				Netaddress: addr.String(),
				Key:        key.Marshal(),
			})

			if err != nil {
				return err
			}

			if !verify.Verified {
				return fmt.Errorf("host key verification failed")
			}

			return nil
		},
	}

	auth := make([]string, 0)
	if upstream.GetNone() != nil {
		config.Auth = append(config.Auth, ssh.NoneAuth())
		auth = append(auth, "none")
	}

	if a := upstream.GetPassword(); a != nil {
		config.Auth = append(config.Auth, ssh.Password(a.GetPassword()))
		auth = append(auth, "password")
	}

	if a := upstream.GetPrivateKey(); a != nil {
		private, err := ssh.ParsePrivateKey(a.GetPrivateKey())
		if err != nil {
			return nil, err
		}
		config.Auth = append(config.Auth, ssh.PublicKeys(private))
		auth = append(auth, "privatekey")
	}

	if a := upstream.GetRemoteSigner(); a != nil {
		rs := remotesigner.New(grpcsigner.New(g.remotesignerClient, a.Meta))
		signer, err := ssh.NewSignerFromSigner(rs)
		if err != nil {
			return nil, err
		}

		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
		auth = append(auth, "remotesigner")
	}

	if len(config.Auth) == 0 {
		log.Warnf("no auth method found for upstream %s, add none auth", addr)
		auth = append(auth, "none")
		config.Auth = append(config.Auth, ssh.NoneAuth())
	}

	log.Debugf("connecting to upstream %v with auth %v", c.RemoteAddr().String(), auth)

	return &ssh.Upstream{
		Conn:         c,
		Address:      addr,
		ClientConfig: config,
	}, nil

}

func (g *GrpcPlugin) NoneAuthCallback(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
	meta := toMeta(challengeCtx, conn)
	reply, err := g.client.NoneAuth(context.Background(), &libplugin.NoneAuthRequest{
		Meta: meta,
	})

	if err != nil {
		return nil, err
	}

	return g.createUpstream(conn, challengeCtx, reply.Upstream)
}

func (g *GrpcPlugin) PasswordCallback(conn ssh.ConnMetadata, password []byte, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
	meta := toMeta(challengeCtx, conn)
	reply, err := g.client.PasswordAuth(context.Background(), &libplugin.PasswordAuthRequest{
		Meta:     meta,
		Password: password,
	})

	if err != nil {
		return nil, err
	}

	return g.createUpstream(conn, challengeCtx, reply.Upstream)
}

func (g *GrpcPlugin) PublicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
	meta := toMeta(challengeCtx, conn)
	reply, err := g.client.PublicKeyAuth(context.Background(), &libplugin.PublicKeyAuthRequest{
		Meta:      meta,
		PublicKey: key.Marshal(),
	})

	if err != nil {
		return nil, err
	}

	return g.createUpstream(conn, challengeCtx, reply.Upstream)
}

func (g *GrpcPlugin) KeyboardInteractiveCallback(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {

	stream, err := g.client.KeyboardInteractiveAuth(context.Background())
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = stream.CloseSend()
	}()

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil, nil
		}

		if err != nil {
			return nil, err
		}

		if r := msg.GetPromptRequest(); r != nil {
			var questions []string
			var echo []bool

			for _, q := range r.GetQuestions() {
				questions = append(questions, q.GetText())
				echo = append(echo, q.GetEcho())
			}

			ans, err := client(r.GetName(), r.GetInstruction(), questions, echo)
			if err != nil {
				return nil, err
			}

			if len(questions) > 0 {
				if err := stream.Send(&libplugin.KeyboardInteractiveAuthMessage{
					Message: &libplugin.KeyboardInteractiveAuthMessage_UserResponse{
						UserResponse: &libplugin.KeyboardInteractiveUserResponse{
							Answers: ans,
						},
					},
				}); err != nil {
					return nil, err
				}
			}
		} else if r := msg.GetMetaRequest(); r != nil {
			meta := toMeta(challengeCtx, conn)
			if err := stream.Send(&libplugin.KeyboardInteractiveAuthMessage{
				Message: &libplugin.KeyboardInteractiveAuthMessage_MetaResponse{
					MetaResponse: &libplugin.KeyboardInteractiveMetaResponse{
						Meta: meta,
					},
				},
			}); err != nil {
				return nil, err
			}

		} else if r := msg.GetFinishRequest(); r != nil {
			if r.GetUpstream() != nil {
				return g.createUpstream(conn, challengeCtx, r.GetUpstream())
			}

			return nil, fmt.Errorf("auth failed: finish req does not contain upstream")
		}
	}
}

func (g *GrpcPlugin) BannerCallback(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) string {
	meta := toMeta(challengeCtx, conn)
	reply, err := g.client.Banner(context.Background(), &libplugin.BannerRequest{
		Meta: meta,
	})

	if err != nil {
		log.Debugf("failed to get banner: %v", err)
		return ""
	}

	return reply.GetMessage()
}

func (g *GrpcPlugin) RecvLogs(writer io.Writer) error {
	stream, err := g.client.Logs(context.Background(), &libplugin.StartLogRequest{})
	if err != nil {
		return err
	}

	for {
		line, err := stream.Recv()
		if err != nil {
			log.Errorf("recv log error: %v", err)
			return err
		}

		fmt.Fprintln(writer, line.GetMessage())
	}
}

type CmdPlugin struct {
	GrpcPlugin
}

func DialCmd(cmd *exec.Cmd) (*CmdPlugin, error) {
	cmdconn, stderr, err := ioconn.DialCmd(cmd)
	if err != nil {
		return nil, err
	}

	go func() {
		_, _ = io.Copy(log.StandardLogger().Out, stderr)
	}()

	go func() {
		err := cmd.Wait()
		if err != nil {
			log.Errorf("cmd %v error: %v", cmd.Path, err)
		}
	}()

	conn, err := grpc.Dial("", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
		return cmdconn, nil
	}))

	if err != nil {
		return nil, err
	}

	g, err := DialGrpc(conn)

	if err != nil {
		return nil, err
	}

	return &CmdPlugin{*g}, nil
}
