//go:build full || e2e

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/docker/docker/api/types"
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
	dockerSshdMu             sync.Mutex
	dockerSshdBridgeAddr     string
	dockerSshdCmds           map[string]string
	dockerSshdKeys           map[string][]byte
	dockerSshdKeyToContainer map[string]string
}

func newDockerPlugin() (*plugin, error) {
	opts := []client.Opt{
		client.FromEnv,
	}

	if os.Getenv("DOCKER_API_VERSION") == "" {
		opts = append(opts, client.WithVersion("1.44"))
	}

	opts = append(opts, client.WithAPIVersionNegotiation())

	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, err
	}
	return &plugin{
		dockerCli:                cli,
		dockerSshdCmds:           make(map[string]string),
		dockerSshdKeys:           make(map[string][]byte),
		dockerSshdKeyToContainer: make(map[string]string),
	}, nil
}

func (p *plugin) list() ([]pipe, error) {
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
		pipe := pipe{}
		pipe.ClientUsername = c.Labels["sshpiper.username"]
		pipe.ContainerUsername = c.Labels["sshpiper.container_username"]
		pipe.AuthorizedKeys = c.Labels["sshpiper.authorized_keys"]
		pipe.TrustedUserCAKeys = c.Labels["sshpiper.trusted_user_ca_keys"]
		pipe.PrivateKey = c.Labels["sshpiper.private_key"]
		pipe.DockerSshdCmd = c.Labels["sshpiper.docker_sshd_cmd"]
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
			pipes = append(pipes, pipe)
			continue
		}

		// dockerExecEnabled path above supports generated private key; regular sshd path still requires explicit private key.
		if (pipe.AuthorizedKeys != "" || pipe.TrustedUserCAKeys != "") && pipe.PrivateKey == "" {
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

			net, err := p.dockerCli.NetworkInspect(context.Background(), netname, types.NetworkInspectOptions{})
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
