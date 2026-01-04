#!/bin/bash
set -xe

groupadd -f testgroup && \
useradd -m -G testgroup testgroupuser

if [ "${SSHPIPERD_DEBUG}" == "1" ]; then
    echo "enter debug on hold mode"
    echo "run [docker exec -ti e2e_testrunner_1 bash] to run to attach"
    sleep infinity; 
else

    if [ "${SSHPIPERD_SKIP_E2E}" == "1" ]; then
        echo "skipping e2e tests as requested"
    else
        echo "running tests" 
        go test -v .
    fi
    
    if [ "${SSHPIPERD_BENCHMARKS}" == "1" ]; then
        echo "running benchmarks"
        set +e
        go test -v -bench=. -run=^$ -benchtime=60s .
        bench_status=$?
        set -e
        if [ "$bench_status" -ne 0 ]; then
            if [ "${ALLOW_BENCHMARK_FAILURES:-0}" -eq 1 ]; then
                echo "Warning: benchmarks failed with status $bench_status, continuing because ALLOW_BENCHMARK_FAILURES=1"
            else
                echo "Error: benchmarks failed with status $bench_status"
                exit "$bench_status"
            fi
        fi
    fi
fi
