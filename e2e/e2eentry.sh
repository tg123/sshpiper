#!/bin/bash

# use entrypoint.sh to generate the ssh_host_ed25519_key
PLUGIN="dummy_badname/" bash /sshpiperd/entrypoint.sh 2>/dev/null

# Use the ca cert to sign the ssh_host_ed25519_key
ssh-keygen -s cahost/ca -I sshpiper_test -n client_123 /etc/ssh/ssh_host_ed25519_key.pub

if [ "${SSHPIPERD_DEBUG}" == "1" ]; then
    echo "enter debug on hold mode"
    echo "run [docker exec -ti e2e_testrunner_1 bash] to run to attach"
    sleep infinity; 
else 
    go test -v; 
fi