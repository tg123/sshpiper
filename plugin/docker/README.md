# docker plugin for sshpiperd

This plugin queries dockerd for containers and creates pipes to them.

## Usage

```
sshpiperd docker
```

start a container with sshpiper labels

```
docker run -d -e USER_NAME=user -e USER_PASSWORD=pass -e PASSWORD_ACCESS=true -l sshpiper.username=pass -l sshpiper.container_username=user -l sshpiper.port=2222 lscr.io/linuxserver/openssh-server
```

connect to piper

```
ssh -l pass piper
```

### Config docker connection

Docker connection is configured with environment variables below:

<https://pkg.go.dev/github.com/docker/docker/client#FromEnv>

 * DOCKER_HOST: to set the url to the docker server, default "unix:///var/run/docker.sock"
 * DOCKER_API_VERSION: to set the version of the API to reach, leave empty for latest.
 * DOCKER_CERT_PATH: to load the TLS certificates from.
 * DOCKER_TLS_VERIFY: to enable or disable TLS verification, off by default.

### Container Labels for plugin

 * sshpiper.username: username to filter containers by `downstream`'s username. left empty to auth with `authorized_keys` only.
 * sshpiper.container_username: username of container's sshd
 * sshpiper.port: port of container's sshd
 * sshpiper.authorized_keys: authorized_keys to verify against `downstream`. in base64 format
 * sshpiper.private_key: private_key to sent to container's sshd. in base64 format
