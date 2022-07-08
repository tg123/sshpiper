#!/bin/bash

# use entrypoint.sh to generate the ssh_host_rsa_key
PLUGIN="dummy_badname/" bash /sshpiperd/entrypoint.sh 2>/dev/null

if [ "${SSHPIPERD_DEBUG}" == "1" ]; then 
    sleep infinity; 
else 
    go test -v; 
fi