#!/bin/bash
set -x

groupadd -f testgroup && \
useradd -m -G testgroup testgroupuser

if [ "${SSHPIPERD_DEBUG}" == "1" ]; then
    echo "enter debug on hold mode"
    echo "run [docker exec -ti e2e_testrunner_1 bash] to run to attach"
    sleep infinity; 
else 
    go test -v; 
fi
