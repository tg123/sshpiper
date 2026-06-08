//go:build full || e2e

package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	log "github.com/sirupsen/logrus"
)

type pipe struct {
	ClientUsername    string
	ContainerUsername string
	Host              string
	DockerSshdCmd     string
	AuthorizedKeys    string
	TrustedUserCAKeys string
	PrivateKey        string
}

type plugin struct {
	dockerCli *client.Client

	// dockerSshdMu protects docker-sshd bridge state keyed by container ID.
	dockerSshdMu             sync.Mutex
	dockerSshdBridgeAddr     string
	dockerSshdCmds           map[string]string
	dockerSshdKeys           map[string][]byte
	dockerSshdPrivateKeys    map[string]string
	dockerSshdKeyToContainer map[string]string
}

func newDockerPlugin() (*plugin, error) {
	cli, err := client.New(client.FromEnv)
	if err != nil {
		return nil, err
	}
	return &plugin{
		dockerCli:                cli,
		dockerSshdCmds:           make(map[string]string),
		dockerSshdKeys:           make(map[string][]byte),
		dockerSshdPrivateKeys:    make(map[string]string),
		dockerSshdKeyToContainer: make(map[string]string),
	}, nil
}

func (p *plugin) list() ([]pipe, error) {
	res, err := p.dockerCli.ContainerList(context.Background(), client.ContainerListOptions{
		// Filters: make(client.Filters).Add("label", fmt.Sprintf("sshpiper.username=%v", username)),
	})
	if err != nil {
		return nil, err
	}

	var pipes []pipe
	activeDockerSshdContainers := make(map[string]struct{})
	for _, c := range res.Items {
		// TODO: support env?
		pipe := pipe{
			ClientUsername:    c.Labels["sshpiper.username"],
			ContainerUsername: c.Labels["sshpiper.container_username"],
			AuthorizedKeys:    c.Labels["sshpiper.authorized_keys"],
			TrustedUserCAKeys: c.Labels["sshpiper.trusted_user_ca_keys"],
			PrivateKey:        c.Labels["sshpiper.private_key"],
			DockerSshdCmd:     c.Labels["sshpiper.docker_sshd_cmd"],
		}
		dockerExecEnabled := strings.EqualFold(c.Labels["sshpiper.docker_exec_cmd"], "true")

		if pipe.ClientUsername == "" && pipe.AuthorizedKeys == "" && pipe.TrustedUserCAKeys == "" {
			log.Debugf("skipping container %v without sshpiper.username or sshpiper.authorized_keys or sshpiper.trusted_user_ca_keys", c.ID)
			continue
		}

		if dockerExecEnabled {
			if pipe.AuthorizedKeys == "" && pipe.TrustedUserCAKeys == "" {
				log.Errorf("skipping container %v with sshpiper.docker_exec_cmd=true but missing sshpiper.authorized_keys/sshpiper.trusted_user_ca_keys", c.ID)
				continue
			}

			addr, err := p.ensureDockerSshdBridge()
			if err != nil {
				log.Errorf("skipping container %v unable to create docker-sshd bridge: %v", c.ID, err)
				continue
			}

			privateKey, err := p.registerDockerSshdContainer(c.ID, pipe.DockerSshdCmd)
			if err != nil {
				log.Errorf("skipping container %v unable to register docker-sshd key: %v", c.ID, err)
				continue
			}

			pipe.PrivateKey = privateKey
			pipe.Host = addr
			activeDockerSshdContainers[c.ID] = struct{}{}
			pipes = append(pipes, pipe)
			continue
		}

		// dockerExecEnabled path above supports generated private key; regular sshd path still requires explicit private key.
		if (pipe.AuthorizedKeys != "" || pipe.TrustedUserCAKeys != "") && pipe.PrivateKey == "" {
			log.Errorf("skipping container %v without sshpiper.private_key but has sshpiper.authorized_keys or sshpiper.trusted_user_ca_keys", c.ID)
			continue
		}

		var hostcandidates []*network.EndpointSettings

		for _, nw := range c.NetworkSettings.Networks {
			if nw.IPAddress.IsValid() {
				hostcandidates = append(hostcandidates, nw)
			}
		}

		if len(hostcandidates) == 0 {
			return nil, fmt.Errorf("no ip address found for container %v", c.ID)
		}

		// default to first one
		pipe.Host = hostcandidates[0].IPAddress.String()

		if len(hostcandidates) > 1 {
			netname := c.Labels["sshpiper.network"]

			if netname == "" {
				return nil, fmt.Errorf("multiple networks found for container %v, please specify sshpiper.network", c.ID)
			}

			net, err := p.dockerCli.NetworkInspect(context.Background(), netname, client.NetworkInspectOptions{})
			if err != nil {
				log.Warnf("cannot list network %v for container %v: %v", netname, c.ID, err)
				continue
			}

			for _, hostcandidate := range hostcandidates {
				if hostcandidate.NetworkID == net.Network.ID {
					pipe.Host = hostcandidate.IPAddress.String()
					break
				}
			}
		}

		port := c.Labels["sshpiper.port"]
		if port != "" {
			pipe.Host = net.JoinHostPort(pipe.Host, port)
		} else {
			pipe.Host = net.JoinHostPort(pipe.Host, "22")
		}

		pipes = append(pipes, pipe)
	}

	p.syncDockerSshdState(activeDockerSshdContainers)

	return pipes, nil
}
