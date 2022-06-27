package workingdir

import (
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"

	"github.com/tg123/sshpiper/sshpiperd/v0bridge"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func (p *plugin) InstallUpstream(piper *ssh.PiperConfig) error {
	v0bridge.InstallUpstream(piper, p.GetHandler())

	piper.PublicKeyCallback = p.matchPublicKeyInSubDir

	if config.MatchPublicKeyInSubDir {
		old := piper.NextAuthMethods
		piper.NextAuthMethods = func(conn ssh.ConnMetadata, ctx ssh.ChallengeContext) ([]string, error) {
			methods, err := old(conn, ctx)
			methods = append(methods, "publickey")
			return methods, err
		}
	}

	return nil
}

func (p *plugin) matchPublicKeyDir(conn ssh.ConnMetadata, key ssh.PublicKey, user, userdir string) (*ssh.Upstream, error) {
	if !checkUsername(user) {
		return nil, fmt.Errorf("downstream is not using a valid username")
	}

	userUpstreamFile := userFile{filename: userUpstreamFile, userdir: userdir}
	err := userUpstreamFile.checkPerm()

	if os.IsNotExist(err) && len(config.FallbackUsername) > 0 {
		user = config.FallbackUsername
	} else if err != nil {
		return nil, err
	}

	data, err := userUpstreamFile.read()
	if err != nil {
		return nil, err
	}

	host, port, mappedUser, err := parseUpstreamFile(string(data))
	if err != nil {
		return nil, err
	}
	addr := fmt.Sprintf("%v:%v", host, port)

	logger.Printf("mapping user [%v] to [%v@%v]", user, mappedUser, addr)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	hostKeyCallback := ssh.InsecureIgnoreHostKey()

	if config.StrictHostKey {
		userKnownHosts := userFile{filename: userKnownHosts, userdir: userdir}
		hostKeyCallback, err = knownhosts.New(userKnownHosts.realPath())

		if err != nil {
			return nil, err
		}
	}

	signer, err := mapPublicKeyFromUserfile(conn, user, userdir, key)
	if err != nil {
		return nil, err
	}

	if signer == nil {
		return nil, fmt.Errorf("cant find public key in user folder")
	}

	return &ssh.Upstream{
		Conn: c,
		ClientConfig: ssh.ClientConfig{
			User:            mappedUser,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: hostKeyCallback,
		},
	}, nil
}

func (p *plugin) matchPublicKeyInSubDir(conn ssh.ConnMetadata, key ssh.PublicKey, _ ssh.ChallengeContext) (*ssh.Upstream, error) {

	{
		userdir := path.Join(config.WorkingDir, conn.User())
		u, err := p.matchPublicKeyDir(conn, key, conn.User(), userdir)
		if err != nil && !config.MatchPublicKeyInSubDir {
			logger.Errorf("cannot map private key in %v: %v", userdir, err)
			return nil, err
		}

		if u != nil {
			return u, nil
		}
	}

	var upstream *ssh.Upstream

	// search in working dir
	filepath.Walk(config.WorkingDir, func(path string, info os.FileInfo, err error) error {

		logger.Debugf("search public key in path: %v", path)
		if err != nil {
			logger.Debug("error walking path: ", err)
			return nil
		}

		if !info.IsDir() {
			return nil
		}

		u, err := p.matchPublicKeyDir(conn, key, conn.User(), path)
		if err != nil {
			logger.Infof("cannot map private key in %v: %v, search next", path, err)
		}

		if u != nil {
			upstream = u
			return fmt.Errorf("stop")
		}

		return nil
	})

	if upstream != nil {
		return upstream, nil
	}

	return nil, fmt.Errorf("no matching public key found in %v", config.WorkingDir)
}
