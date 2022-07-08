#!/bin/bash

# use entrypoint.sh to generate the ssh_host_rsa_key
PLUGIN="dummy_badname/" bash /sshpiperd/entrypoint.sh 2>/dev/null

if [ "${SSHPIPERD_DEBUG}" == "1" ]; then
    echo "enter debug on hold mode"
    echo "run [docker exec -ti e2e_testrunner_1 bash] to run to attach"
    sleep infinity; 
else 
    go test -v; 
fi