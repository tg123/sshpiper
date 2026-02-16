//go:build full || e2e

package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
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
	dockerSshdMu    sync.Mutex
	dockerSshdAddrs map[string]string
	dockerSshdCmds  map[string]string
	dockerSshdKeys  map[string][]byte
}

func newDockerPlugin() (*plugin, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	return &plugin{
		dockerCli:       cli,
		dockerSshdAddrs: make(map[string]string),
		dockerSshdCmds:  make(map[string]string),
		dockerSshdKeys:  make(map[string][]byte),
	}, nil
}

func (p *plugin) list() ([]pipe, error) {
	// filter := filters.NewArgs()
	// filter.Add("label", fmt.Sprintf("sshpiper.username=%v", username))

	containers, err := p.dockerCli.ContainerList(context.Background(), container.ListOptions{
		// Filters: filter,
	})
	if err != nil {
		return nil, err
	}

	var pipes []pipe
	for _, c := range containers {
		// TODO: support env?
		pipe := pipe{}
		pipe.ClientUsername = c.Labels["sshpiper.username"]
		pipe.ContainerUsername = c.Labels["sshpiper.container_username"]
		pipe.AuthorizedKeys = c.Labels["sshpiper.authorized_keys"]
		pipe.TrustedUserCAKeys = c.Labels["sshpiper.trusted_user_ca_keys"]
		pipe.PrivateKey = c.Labels["sshpiper.private_key"]
		pipe.DockerSshdCmd = c.Labels["sshpiper.docker_sshd_cmd"]
		dockerSSHD := strings.EqualFold(c.Labels["sshpiper.docker_sshd"], "true")

		if pipe.ClientUsername == "" && pipe.AuthorizedKeys == "" && pipe.TrustedUserCAKeys == "" {
			log.Debugf("skipping container %v without sshpiper.username or sshpiper.authorized_keys or sshpiper.trusted_user_ca_keys", c.ID)
			continue
		}

		if (pipe.AuthorizedKeys != "" || pipe.TrustedUserCAKeys != "") && pipe.PrivateKey == "" {
			log.Errorf("skipping container %v without sshpiper.private_key but has sshpiper.authorized_keys or sshpiper.trusted_user_ca_keys", c.ID)
			continue
		}

		if dockerSSHD {
			if pipe.PrivateKey == "" || (pipe.AuthorizedKeys == "" && pipe.TrustedUserCAKeys == "") {
				log.Errorf("skipping container %v with sshpiper.docker_sshd=true but missing sshpiper.private_key or sshpiper.authorized_keys/sshpiper.trusted_user_ca_keys", c.ID)
				continue
			}

			addr, err := p.dockerSshdAddr(c.ID, pipe.PrivateKey, pipe.DockerSshdCmd)
			if err != nil {
				log.Errorf("skipping container %v unable to create docker-sshd bridge: %v", c.ID, err)
				continue
			}

			pipe.Host = addr
			pipes = append(pipes, pipe)
			continue
		}

		var hostcandidates []*network.EndpointSettings

		for _, network := range c.NetworkSettings.Networks {
			if network.IPAddress != "" {
				hostcandidates = append(hostcandidates, network)
			}
		}

		if len(hostcandidates) == 0 {
			return nil, fmt.Errorf("no ip address found for container %v", c.ID)
		}

		// default to first one
		pipe.Host = hostcandidates[0].IPAddress

		if len(hostcandidates) > 1 {
			netname := c.Labels["sshpiper.network"]

			if netname == "" {
				return nil, fmt.Errorf("multiple networks found for container %v, please specify sshpiper.network", c.ID)
			}

			net, err := p.dockerCli.NetworkInspect(context.Background(), netname, network.InspectOptions{})
			if err != nil {
				log.Warnf("cannot list network %v for container %v: %v", netname, c.ID, err)
				continue
			}

			for _, hostcandidate := range hostcandidates {
				if hostcandidate.NetworkID == net.ID {
					pipe.Host = hostcandidate.IPAddress
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

	return pipes, nil
}
