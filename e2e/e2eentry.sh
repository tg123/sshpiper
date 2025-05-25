#!/bin/bash
set -x

# Run sshpiper with a fake plugin name to generate the file: /etc/ssh/ssh_host_ed25519_key
SSHPIPERD_SERVER_KEY_GENERATE_MODE=notexist /sshpiperd/sshpiperd not-a-real-plugin 2>/dev/null

groupadd -f testgroup && \
useradd -m -G testgroup testgroupuser

if [ "${SSHPIPERD_DEBUG}" == "1" ]; then
    echo "enter debug on hold mode"
    echo "run [docker exec -ti e2e_testrunner_1 bash] to run to attach"
    sleep infinity; 
else 
    go test -v; 
fi
