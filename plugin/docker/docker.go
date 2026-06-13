//go:build full || e2e

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
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
			slog.Debug("skipping container without required labels", "container_id", c.ID)
			continue
		}

		if dockerExecEnabled {
			if pipe.AuthorizedKeys == "" && pipe.TrustedUserCAKeys == "" {
				slog.Error("skipping container with sshpiper.docker_exec_cmd=true but missing sshpiper.authorized_keys/sshpiper.trusted_user_ca_keys", "container_id", c.ID)
				continue
			}

			addr, err := p.ensureDockerSshdBridge()
			if err != nil {
				slog.Error("skipping container unable to create docker-sshd bridge", "container_id", c.ID, "error", err)
				continue
			}

			privateKey, err := p.registerDockerSshdContainer(c.ID, pipe.DockerSshdCmd)
			if err != nil {
				slog.Error("skipping container unable to register docker-sshd key", "container_id", c.ID, "error", err)
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
			slog.Error("skipping container missing sshpiper.private_key while auth labels exist", "container_id", c.ID)
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
				slog.Warn("cannot list network for container", "network", netname, "container_id", c.ID, "error", err)
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
