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
        bench_output=$(mktemp)
        chmod 600 "${bench_output}"
        trap 'rm -f "${bench_output}"' EXIT
        go test -v -bench=. -run=^$ -benchtime=60s . | tee "${bench_output}"
        bench_exit_code=${PIPESTATUS[0]}

        if [ ${bench_exit_code} -ne 0 ]; then
            exit ${bench_exit_code}
        fi

        echo "benchmark summary (sshpiper vs baseline)"
        awk '
            BEGIN { bench_count = split("scp_upload ssh_stream", bench_order, " ") }

            function record(kind, name, val) {
                bench_data[kind ":" name] = val
            }

            /^BenchmarkTransferRate\/scp_upload-/ { record("sshpiper", "scp_upload", $(NF-1)) }
            /^BenchmarkTransferRate\/ssh_stream-/ { record("sshpiper", "ssh_stream", $(NF-1)) }
            /^BenchmarkTransferRateBaseline\/scp_upload-/ { record("baseline", "scp_upload", $(NF-1)) }
            /^BenchmarkTransferRateBaseline\/ssh_stream-/ { record("baseline", "ssh_stream", $(NF-1)) }

            END {
                for (i = 1; i <= bench_count; i++) {
                    name = bench_order[i]
                    base = bench_data["baseline:" name]
                    piper = bench_data["sshpiper:" name]

                    if (base == "" || piper == "") {
                        printf("  %s: missing data (baseline=%s sshpiper=%s)\n", name, base, piper)
                        continue
                    }

                    ratio = piper / base * 100
                    printf("  %s: sshpiper %s MB/s vs baseline %s MB/s (%.1f%%)\n", name, piper, base, ratio)
                }
            }
        ' "${bench_output}"

        rm -f "${bench_output}"
        trap - EXIT
    fi
fi
