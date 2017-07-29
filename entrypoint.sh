#!/bin/bash
set -euo pipefail


if [ ! -f /etc/ssh/ssh_host_rsa_key ];then
    ssh-keygen -f /etc/ssh/ssh_host_rsa_key -N '' -t rsa
fi

exec "$@"
