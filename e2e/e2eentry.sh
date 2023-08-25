#!/bin/bash

# use entrypoint.sh to generate the ssh_host_ed25519_key
PLUGIN="dummy_badname/" bash /sshpiperd/entrypoint.sh 2>/dev/null

# Create an ssh key pair and then sign the public key with the ca cert
chmod 600 cahost/ca
ssh-keygen -t ssh-ed25519 -f /etc/ssh/ssh_user -N ""
ssh-keygen -s cahost/ca -I ssh_user -n client_123 /etc/ssh/ssh_user.pub

if [ "${SSHPIPERD_DEBUG}" == "1" ]; then
    echo "enter debug on hold mode"
    echo "run [docker exec -ti e2e_testrunner_1 bash] to run to attach"
    sleep infinity; 
else 
    go test -v; 
fi