package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

type pipe struct {
	ClientUsername    string
	ContainerUsername string
	Host              string
	AuthorizedKeys    string
	PrivateKey        string
}

type plugin struct {
	dockerCli *client.Client
}

func newDockerPlugin() (*plugin, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, err
	}
	return &plugin{
		dockerCli: cli,
	}, nil
}

func (p *plugin) listPipes() ([]pipe, error) {
	// filter := filters.NewArgs()
	// filter.Add("label", fmt.Sprintf("sshpiper.username=%v", username))

	containers, err := p.dockerCli.ContainerList(context.Background(), types.ContainerListOptions{
		// Filters: filter,
	})
	if err != nil {
		return nil, err
	}

	var pipes []pipe
	for _, c := range containers {
		// TODO: support env?
		p := pipe{}
		p.ClientUsername = c.Labels["sshpiper.username"]
		p.ContainerUsername = c.Labels["sshpiper.container_username"]
		p.AuthorizedKeys = c.Labels["sshpiper.authorized_keys"]
		p.PrivateKey = c.Labels["sshpiper.private_key"]

		if p.ClientUsername == "" && p.AuthorizedKeys == "" {
			log.Debugf("skipping container %v without sshpiper.username or sshpiper.authorized_keys or sshpiper.private_key", c.ID)
			continue
		}

		if p.AuthorizedKeys != "" && p.PrivateKey == "" {
			log.Errorf("skipping container %v without sshpiper.private_key but has sshpiper.authorized_keys", c.ID)
			continue
		}

		for _, network := range c.NetworkSettings.Networks {
			if network.IPAddress != "" {
				port := c.Labels["sshpiper.port"]
				if port == "" {
					p.Host = network.IPAddress // default 22
				} else {
					p.Host = net.JoinHostPort(network.IPAddress, port)
				}
			}
		}

		pipes = append(pipes, p)
	}

	return pipes, nil
}

func (p *plugin) supportedMethods() ([]string, error) {
	pipes, err := p.listPipes()
	if err != nil {
		return nil, err
	}

	set := make(map[string]bool)

	for _, pipe := range pipes {
		if pipe.AuthorizedKeys != "" {
			set["publickey"] = true // found authorized_keys, so we support publickey
		} else {
			set["password"] = true // no authorized_keys, so we support password
		}
	}

	var methods []string
	for k := range set {
		methods = append(methods, k)
	}
	return methods, nil
}

func (p *plugin) createUpstream(conn libplugin.ConnMetadata, to pipe, originPassword string) (*libplugin.Upstream, error) {
	host, port, err := libplugin.SplitHostPortForSSH(to.Host)
	if err != nil {
		return nil, err
	}

	u := &libplugin.Upstream{
		Host:          host,
		Port:          int32(port),
		UserName:      to.ContainerUsername,
		IgnoreHostKey: true,
	}

	// password found
	if originPassword != "" {
		u.Auth = libplugin.CreatePasswordAuth([]byte(originPassword))
		return u, nil
	}

	// try private key
	data, err := base64.StdEncoding.DecodeString(to.PrivateKey)
	if err != nil {
		return nil, err
	}

	if data != nil {
		u.Auth = libplugin.CreatePrivateKeyAuth(data)
		return u, nil
	}

	return nil, fmt.Errorf("no password or private key found")
}

func (p *plugin) findAndCreateUpstream(conn libplugin.ConnMetadata, password string, publicKey []byte) (*libplugin.Upstream, error) {
	user := conn.User()

	pipes, err := p.listPipes()
	if err != nil {
		return nil, err
	}

	for _, pipe := range pipes {

		// test password
		if publicKey == nil {
			if pipe.ClientUsername != user {
				continue
			}

			return p.createUpstream(conn, pipe, password)
		}

		// test public key
		if pipe.ClientUsername != "" {
			if pipe.ClientUsername != user {
				continue
			}
		}

		// ignore username and match all
		rest, err := base64.RawStdEncoding.DecodeString(pipe.AuthorizedKeys)
		if err != nil {
			return nil, err
		}

		var authedPubkey ssh.PublicKey
		for len(rest) > 0 {
			authedPubkey, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
			if err != nil {
				return nil, err
			}

			if bytes.Equal(authedPubkey.Marshal(), publicKey) {
				return p.createUpstream(conn, pipe, "")
			}
		}
	}

	return nil, fmt.Errorf("no matching pipe for username [%v] found", user)
}
