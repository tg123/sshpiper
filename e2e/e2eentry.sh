#!/bin/bash
set -x

# use entrypoint.sh to generate the ssh_host_ed25519_key
PLUGIN="dummy_badname/" bash /sshpiperd/entrypoint.sh 2>/dev/null

groupadd -f testgroup && \
useradd -m -G testgroup testuser

if [ "${SSHPIPERD_DEBUG}" == "1" ]; then
    echo "enter debug on hold mode"
    echo "run [docker exec -ti e2e_testrunner_1 bash] to run to attach"
    sleep infinity; 
else 
    go test -v; 
fi
