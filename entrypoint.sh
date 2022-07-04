#!/bin/sh
set -euo pipefail


if [ ! -f /etc/ssh/ssh_host_rsa_key ];then
    /ssh-keygen -t rsa -N '' -f /etc/ssh/ssh_host_rsa_key
fi

exec "$@"
