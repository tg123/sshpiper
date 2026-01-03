#!/bin/bash
set -xe

groupadd -f testgroup && \
useradd -m -G testgroup testgroupuser

if [ "${SSHPIPERD_DEBUG}" == "1" ]; then
    echo "enter debug on hold mode"
    echo "run [docker exec -ti e2e_testrunner_1 bash] to run to attach"
    sleep infinity; 
else
    echo "running tests" 
    go test -v .
    
    echo "running benchmarks"
    go test -v -bench=. -run=^$ -count=10 .;
fi
