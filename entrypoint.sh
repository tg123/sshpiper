#!/bin/sh
set -eo pipefail

if [ -z "$SSHPIPERD_SERVER_KEY" ]; then
    if [ ! -f /etc/ssh/ssh_host_ed25519_key ];then
        ssh-keygen -t rsa -N '' -f /etc/ssh/ssh_host_ed25519_key
    fi
fi

PLUGIN=${PLUGIN:-workingdir}

exec /sshpiperd/sshpiperd /sshpiperd/plugins/$PLUGIN