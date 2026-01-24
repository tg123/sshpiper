//go:build full || e2e

package main

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"
)

type pipe struct {
	ClientUsername    string
	ContainerUsername string
	Host              string
	AuthorizedKeys    string
	TrustedUserCAKeys string
	PrivateKey        string
}

const (
	dockerSshdLabel       = "sshpiper.docker_sshd"
	dockerSshdDefaultPort = "2232"
)

type plugin struct {
	dockerCli *client.Client
}

func newDockerPlugin() (*plugin, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	return &plugin{
		dockerCli: cli,
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

		hasPubKey := pipe.AuthorizedKeys != "" || pipe.TrustedUserCAKeys != ""
		dockerSshd := strings.EqualFold(c.Labels[dockerSshdLabel], "true")

		if pipe.ClientUsername == "" && !hasPubKey {
			log.Debugf("skipping container %v without sshpiper.username or sshpiper.authorized_keys or sshpiper.trusted_user_ca_keys", c.ID)
			continue
		}

		if dockerSshd {
			pipe.ContainerUsername = c.ID
			if !hasPubKey {
				log.Errorf("skipping container %v without sshpiper.authorized_keys or sshpiper.trusted_user_ca_keys for docker-sshd", c.ID)
				continue
			}
			if pipe.PrivateKey == "" {
				log.Errorf("skipping container %v without sshpiper.private_key for docker-sshd", c.ID)
				continue
			}

			pipe.Host = net.JoinHostPort("127.0.0.1", dockerSshdDefaultPort)
			pipes = append(pipes, pipe)
			continue
		}

		if hasPubKey && pipe.PrivateKey == "" {
			log.Errorf("skipping container %v without sshpiper.private_key but has sshpiper.authorized_keys or sshpiper.trusted_user_ca_keys", c.ID)
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
