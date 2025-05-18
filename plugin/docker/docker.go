//go:build full || e2e

package main

import (
	"context"
	"fmt"
	"net"

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
		pipe.PrivateKey = c.Labels["sshpiper.private_key"]

		if pipe.ClientUsername == "" && pipe.AuthorizedKeys == "" {
			log.Debugf("skipping container %v without sshpiper.username or sshpiper.authorized_keys or sshpiper.private_key", c.ID)
			continue
		}

		if pipe.AuthorizedKeys != "" && pipe.PrivateKey == "" {
			log.Errorf("skipping container %v without sshpiper.private_key but has sshpiper.authorized_keys", c.ID)
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
		}

		pipes = append(pipes, pipe)
	}

	return pipes, nil
}
