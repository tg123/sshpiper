package plugin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"net/url"
	"os/exec"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/docker-sshd/pkg/bridge"
	"github.com/tg123/remotesigner"
	"github.com/tg123/remotesigner/grpcsigner"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/libplugin/ioconn"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type GrpcPluginConfig struct {
	ssh.PiperConfig

	PipeCreateErrorCallback func(conn net.Conn, err error)
	PipeStartCallback       func(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext)
	PipeErrorCallback       func(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext, err error)
}

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

func (g *GrpcPlugin) InstallPiperConfig(config *GrpcPluginConfig) error {
	cb, err := g.client.ListCallbacks(context.Background(), &libplugin.ListCallbackRequest{})
	if err != nil {
		return err
	}

	config.CreateChallengeContext = func(conn ssh.ServerPreAuthConn) (ssh.ChallengeContext, error) {
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

				log.Debugf("next auth methods %v for downstream  %v (username [%v])", methods, conn.RemoteAddr().String(), conn.User())
				return methods, err
			}

		case "NoneAuth":
			config.NoClientAuthCallback = func(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
				log.Debugf("downstream %v (username [%v]) is sending none auth", conn.RemoteAddr().String(), conn.User())
				u, err := g.NoClientAuthCallback(conn, challengeCtx)
				if err != nil {
					log.Errorf("cannot create upstream for %v (username [%v]) with none auth: %v", conn.RemoteAddr().String(), conn.User(), err)
				}
				return u, err
			}
		case "PasswordAuth":
			config.PasswordCallback = func(conn ssh.ConnMetadata, password []byte, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
				log.Debugf("downstream %v (username [%v]) is sending password auth", conn.RemoteAddr().String(), conn.User())
				u, err := g.PasswordCallback(conn, password, challengeCtx)
				if err != nil {
					log.Errorf("cannot create upstream for %v (username [%v]) with password auth: %v", conn.RemoteAddr().String(), conn.User(), err)
				}
				return u, err
			}
		case "PublicKeyAuth":
			config.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
				log.Debugf("downstream %v (username [%v]) is sending public key auth", conn.RemoteAddr().String(), conn.User())
				u, err := g.PublicKeyCallback(conn, key, challengeCtx)
				if err != nil {
					log.Errorf("cannot create upstream for %v (username [%v]) with public key auth: %v", conn.RemoteAddr().String(), conn.User(), err)
				}
				return u, err
			}
		case "KeyboardInteractiveAuth":
			config.KeyboardInteractiveCallback = func(conn ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
				log.Debugf("downstream %v (username [%v]) is sending keyboard interactive auth", conn.RemoteAddr().String(), conn.User())
				u, err := g.KeyboardInteractiveCallback(conn, challenge, challengeCtx)
				if err != nil {
					log.Errorf("cannot create upstream for %v (username [%v]) with keyboard interactive auth: %v", conn.RemoteAddr().String(), conn.User(), err)
				}
				return u, err
			}
		case "UpstreamAuthFailure":
			config.UpstreamAuthFailureCallback = func(conn ssh.ConnMetadata, method string, err error, challengeCtx ssh.ChallengeContext) {
				log.Debugf("upstream rejected [%v] auth: %v from downstream %v (username [%v])", method, err, conn.RemoteAddr().String(), conn.User())
				g.UpstreamAuthFailureCallbackRemote(conn, method, err, challengeCtx)
			}
		case "Banner":
			config.DownstreamBannerCallback = g.DownstreamBannerCallback
		case "VerifyHostKey":
			// ignore
		case "PipeStart":
			config.PipeStartCallback = g.PipeStartCallback
		case "PipeError":
			config.PipeErrorCallback = g.PipeErrorCallback
		case "PipeCreateError":
			config.PipeCreateErrorCallback = g.PipeCreateErrorCallback
		default:
			return fmt.Errorf("unknown callback %s", c)
		}
	}

	return nil
}

func (g *GrpcPlugin) CreatePiperConfig() (*GrpcPluginConfig, error) {
	config := &GrpcPluginConfig{}
	return config, g.InstallPiperConfig(config)
}

type PluginConnMeta libplugin.ConnMeta

// ChallengedUsername implements ssh.ChallengeContext
func (m *PluginConnMeta) ChallengedUsername() string {
	return m.UserName
}

// Meta implements ssh.ChallengeContext
func (m *PluginConnMeta) Meta() interface{} {
	return m
}

func (g *GrpcPlugin) CreateChallengeContext(conn ssh.ServerPreAuthConn) (ssh.ChallengeContext, error) {
	uiq, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	meta := PluginConnMeta{
		UserName: conn.User(),
		FromAddr: conn.RemoteAddr().String(),
		UniqId:   uiq.String(),
		Metadata: make(map[string]string),
	}

	return &meta, g.NewConnection(&meta)
}

func (g *GrpcPlugin) NewConnection(meta *PluginConnMeta) error {
	if g.hasNewConnectionCallback {
		_, err := g.client.NewConnection(context.Background(), &libplugin.NewConnectionRequest{
			Meta: &libplugin.ConnMeta{
				UserName: meta.UserName,
				FromAddr: meta.FromAddr,
				UniqId:   meta.UniqId,
				Metadata: meta.Metadata,
			},
		})

		return err
	}

	return nil
}

func toMeta(challengeCtx ssh.ChallengeContext, conn ssh.ConnMetadata) *libplugin.ConnMeta {
	switch meta := challengeCtx.(type) {
	case *PluginConnMeta:
		meta.UserName = conn.User()
		return (*libplugin.ConnMeta)(meta)
	case *chainConnMeta:
		meta.UserName = conn.User()
		return (*libplugin.ConnMeta)(&meta.PluginConnMeta)
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

	// ugly way to support meta set
	if retry := upstream.GetRetryCurrentPlugin(); retry != nil {
		if meta.Metadata == nil {
			meta.Metadata = make(map[string]string)
		}

		for k, v := range retry.Meta {
			meta.Metadata[k] = v
		}

		return nil, fmt.Errorf("client retry requested")
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

	config.SetDefaults()

	auth := make([]string, 0)
	dockerSshdAllowedPublicKeys := make([]ssh.PublicKey, 0)
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

		if caPublicKeyByte := a.GetCaPublicKey(); caPublicKeyByte != nil {
			caPublicKey, _, _, _, err := ssh.ParseAuthorizedKey(caPublicKeyByte)
			if err != nil {
				return nil, err
			}

			caCertificate, ok := caPublicKey.(*ssh.Certificate)
			if !ok {
				return nil, fmt.Errorf("failed to convert the caPublicKey to an ssh.Certificate")
			}

			private, err = ssh.NewCertSigner(caCertificate, private)
			if err != nil {
				return nil, err
			}
		}

		config.Auth = append(config.Auth, ssh.PublicKeys(private))
		auth = append(auth, "privatekey")
		dockerSshdAllowedPublicKeys = append(dockerSshdAllowedPublicKeys, private.PublicKey())
	}

	if a := upstream.GetRemoteSigner(); a != nil {
		rs := remotesigner.New(grpcsigner.New(g.remotesignerClient, a.Meta))
		signer, err := ssh.NewSignerFromSigner(rs)
		if err != nil {
			return nil, err
		}

		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
		auth = append(auth, "remotesigner")
		dockerSshdAllowedPublicKeys = append(dockerSshdAllowedPublicKeys, signer.PublicKey())
	}

	upstreamUri := upstream.GetOrGenerateUri()

	if len(config.Auth) == 0 {
		log.Warnf("no auth method found for downstream %s to upstream %s, add none auth", conn.RemoteAddr().String(), upstreamUri)
		auth = append(auth, "none")
		config.Auth = append(config.Auth, ssh.NoneAuth())
	}

	upstreamConn, addr, err := g.dialUpstream(upstreamUri, dockerSshdAllowedPublicKeys)
	if err != nil {
		return nil, err
	}

	log.Debugf("connecting to upstream %v@%v with auth %v", config.User, upstreamConn.RemoteAddr().String(), auth)

	return &ssh.Upstream{
		Conn:         upstreamConn,
		Address:      addr,
		ClientConfig: config,
	}, nil
}

func (g *GrpcPlugin) dialUpstream(uri string, dockerSshdAllowedPublicKeys []ssh.PublicKey) (net.Conn, string, error) {
	var addr string
	var network string

	if len(uri) == 0 {
		return nil, "", fmt.Errorf("empty upstream uri")
	}

	u, err := url.Parse(uri)
	if err != nil {
		return nil, "", fmt.Errorf("invalid upstream uri: %w", err)
	}

	network = u.Scheme
	addr = u.Host
	if addr == "" {
		addr = u.Opaque
	}
	if addr == "" {
		return nil, "", fmt.Errorf("invalid upstream uri, missing address: %s", uri)
	}

	if network == "docker-sshd" {
		if len(dockerSshdAllowedPublicKeys) == 0 {
			return nil, "", fmt.Errorf("docker-sshd upstream requires publickey auth")
		}

		conn, err := g.dialDockerSshdUpstream(addr, dockerSshdAllowedPublicKeys)
		if err != nil {
			return nil, "", err
		}

		return conn, addr, nil
	}

	upstreamConn, err := net.Dial(network, addr)
	if err != nil {
		return nil, "", err
	}

	return upstreamConn, addr, nil
}

func (g *GrpcPlugin) dialDockerSshdUpstream(containerID string, allowedPublicKeys []ssh.PublicKey) (net.Conn, error) {
	dockerCli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}

	_, hostPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	hostSigner, err := ssh.NewSignerFromKey(hostPrivateKey)
	if err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	type acceptResult struct {
		conn      net.Conn
		acceptErr error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		conn, err := listener.Accept()
		acceptCh <- acceptResult{conn: conn, acceptErr: err}
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		return nil, err
	}

	var accepted acceptResult
	select {
	case accepted = <-acceptCh:
	case <-time.After(5 * time.Second):
		_ = clientConn.Close()
		_ = listener.Close()
		return nil, fmt.Errorf("timeout waiting for local docker-sshd bridge accept")
	}
	_ = listener.Close()
	if accepted.acceptErr != nil {
		_ = clientConn.Close()
		return nil, accepted.acceptErr
	}
	serverConn := accepted.conn

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			matched := false
			for _, k := range allowedPublicKeys {
				if subtle.ConstantTimeCompare(k.Marshal(), key.Marshal()) == 1 {
					matched = true
				}
			}

			if matched {
				return nil, nil
			}

			return nil, fmt.Errorf("unexpected public key for docker-sshd upstream")
		},
	}
	serverConfig.AddHostKey(hostSigner)

	b, err := bridge.New(serverConn, serverConfig, &bridge.BridgeConfig{
		DefaultCmd: "/bin/sh",
	}, func(sc *ssh.ServerConn) (bridge.SessionProvider, error) {
		return &dockerSshdSessionProvider{containerID: containerID, dockerCli: dockerCli}, nil
	})
	if err != nil {
		_ = serverConn.Close()
		_ = clientConn.Close()
		return nil, err
	}

	go b.Start()

	return clientConn, nil
}

const dockerExecInspectTimeout = 10 * time.Second
const dockerExecInspectRetryInterval = 100 * time.Millisecond

type dockerSshdSessionProvider struct {
	containerID string
	dockerCli   *client.Client
	execID      string
	initSize    bridge.ResizeOptions
}

func (d *dockerSshdSessionProvider) Exec(ctx context.Context, execconfig bridge.ExecConfig) (<-chan bridge.ExecResult, error) {
	initialSize := d.initSize
	if initialSize.Width == 0 || initialSize.Height == 0 {
		initialSize = bridge.ResizeOptions{
			Width:  80,
			Height: 24,
		}
	}

	exec, err := d.dockerCli.ContainerExecCreate(ctx, d.containerID, container.ExecOptions{
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: !execconfig.Tty, // stderr is already merged in tty mode
		Tty:          execconfig.Tty,
		Env:          execconfig.Env,
		Cmd:          execconfig.Cmd,
		ConsoleSize:  &[2]uint{initialSize.Height, initialSize.Width},
	})
	if err != nil {
		return nil, err
	}

	d.execID = exec.ID
	attach, err := d.dockerCli.ContainerExecAttach(ctx, d.execID, container.ExecAttachOptions{
		Tty: execconfig.Tty,
	})
	if err != nil {
		return nil, err
	}

	r := make(chan bridge.ExecResult, 1)

	go func() {
		defer attach.Close()

		done := make(chan error, 1)
		go func() {
			_, err := io.Copy(execconfig.Output, attach.Reader)
			done <- err
		}()
		go func() {
			_, _ = io.Copy(attach.Conn, execconfig.Input)
		}()

		var ioErr error
		select {
		case ioErr = <-done:
		case <-ctx.Done():
			r <- bridge.ExecResult{ExitCode: -1, Error: ctx.Err()}
			return
		}

		exitCode := -1
		st := time.Now()
		for {
			select {
			case <-ctx.Done():
				r <- bridge.ExecResult{ExitCode: -1, Error: ctx.Err()}
				return
			default:
			}

			if time.Since(st) > dockerExecInspectTimeout {
				break
			}

			exec, err := d.dockerCli.ContainerExecInspect(ctx, d.execID)
			if err != nil {
				time.Sleep(dockerExecInspectRetryInterval)
				continue
			}
			if exec.Running {
				time.Sleep(dockerExecInspectRetryInterval)
				continue
			}
			exitCode = exec.ExitCode
			break
		}

		if exitCode == 0 && ioErr == io.EOF {
			ioErr = nil
		}

		r <- bridge.ExecResult{ExitCode: exitCode, Error: ioErr}
	}()

	return r, nil
}

func (d *dockerSshdSessionProvider) Resize(ctx context.Context, size bridge.ResizeOptions) error {
	if d.execID == "" {
		d.initSize = size
		return nil
	}

	return d.dockerCli.ContainerExecResize(ctx, d.execID, container.ResizeOptions{
		Height: size.Height,
		Width:  size.Width,
	})
}

func (g *GrpcPlugin) NoClientAuthCallback(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) (*ssh.Upstream, error) {
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

func (g *GrpcPlugin) DownstreamBannerCallback(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) string {
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

func (g *GrpcPlugin) PipeCreateErrorCallback(conn net.Conn, err error) {
	_, _ = g.client.PipeCreateErrorNotice(context.Background(), &libplugin.PipeCreateErrorNoticeRequest{
		FromAddr: conn.RemoteAddr().String(),
		Error:    err.Error(),
	})
}

func (g *GrpcPlugin) PipeStartCallback(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext) {
	meta := toMeta(challengeCtx, conn)
	_, _ = g.client.PipeStartNotice(context.Background(), &libplugin.PipeStartNoticeRequest{
		Meta: meta,
	})
}

func (g *GrpcPlugin) PipeErrorCallback(conn ssh.ConnMetadata, challengeCtx ssh.ChallengeContext, pipeerr error) {
	meta := toMeta(challengeCtx, conn)
	_, _ = g.client.PipeErrorNotice(context.Background(), &libplugin.PipeErrorNoticeRequest{
		Meta:  meta,
		Error: pipeerr.Error(),
	})
}

func (g *GrpcPlugin) RecvLogs(writer io.Writer) error {
	uid, err := uuid.NewRandom()
	if err != nil {
		return err
	}

	stream, err := g.client.Logs(context.Background(), &libplugin.StartLogRequest{
		UniqId: uid.String(),
		Level:  log.GetLevel().String(),
		Tty:    checkIfTerminal(log.StandardLogger().Out),
	})
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
	Quit <-chan error
}

func DialCmd(cmd *exec.Cmd) (*CmdPlugin, error) {
	cmdconn, stderr, err := ioconn.DialCmd(cmd)
	if err != nil {
		return nil, err
	}

	go func() {
		_, _ = io.Copy(log.StandardLogger().Out, stderr)
	}()

	ch := make(chan error, 1)
	go func() {
		ch <- cmd.Wait()
	}()

	// this dummy 127.0.0.1 is not used
	conn, err := grpc.NewClient("127.0.0.1", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
		return cmdconn, nil
	}))
	if err != nil {
		return nil, err
	}

	g, err := DialGrpc(conn)
	if err != nil {
		return nil, err
	}

	return &CmdPlugin{GrpcPlugin: *g, Quit: ch}, nil
}

func GetUniqueID(ctx ssh.ChallengeContext) string {
	switch meta := ctx.(type) {
	case *PluginConnMeta:
		return meta.UniqId
	case *chainConnMeta:
		return meta.UniqId
	}
	panic("unknown challenge context")
}
