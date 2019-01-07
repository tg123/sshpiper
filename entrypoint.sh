#!/bin/sh
set -euo pipefail


if [ ! -f /etc/ssh/ssh_host_rsa_key ];then
    /sshpiperd genkey > /etc/ssh/ssh_host_rsa_key
fi

exec "$@"
