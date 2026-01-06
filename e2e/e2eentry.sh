#!/bin/bash
set -xeo pipefail

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
        old_umask=$(umask)
        umask 077
        bench_output=$(mktemp)
        umask "${old_umask}"
        chmod 600 "${bench_output}"
        trap "rm -f \"${bench_output}\"" EXIT
        go test -v -bench=. -run=^$ -benchtime=60s . | tee "${bench_output}"
        bench_exit_code=$?

        if [ "${bench_exit_code}" -ne 0 ]; then
            exit ${bench_exit_code}
        fi

        echo "benchmark summary (sshpiper vs baseline)"
        bench_cases="scp_upload ssh_stream"
        awk -v bench_cases="${bench_cases}" '
            BEGIN {
                bench_count = split(bench_cases, bench_order, " ")
                for (i = 1; i <= bench_count; i++) {
                    bench_names[bench_order[i]] = 1
                }
            }

            function record(kind, name, val) {
                if (name in bench_names) {
                    bench_data[kind ":" name] = val
                }
            }

            function maybe_record(kind, name, line) {
                if (name == "" || !(name in bench_names)) {
                    return
                }

                if (!match(line, /([0-9]+(\.[0-9]+)?)[[:blank:]]+MB\/s/, val)) {
                    return
                }

                record(kind, name, val[1])
            }

            {
                if (match($1, /^BenchmarkTransferRate\/([^-]+)-/, m)) {
                    maybe_record("sshpiper", m[1], $0)
                } else if (match($1, /^BenchmarkTransferRateBaseline\/([^-]+)-/, m)) {
                    maybe_record("baseline", m[1], $0)
                }
            }

            END {
                for (i = 1; i <= bench_count; i++) {
                    name = bench_order[i]
                    base_key = "baseline:" name
                    piper_key = "sshpiper:" name

                    if (!(base_key in bench_data) || !(piper_key in bench_data)) {
                        base_print = (base_key in bench_data) ? bench_data[base_key] : "N/A"
                        piper_print = (piper_key in bench_data) ? bench_data[piper_key] : "N/A"
                        printf("  %s: missing data (baseline=%s sshpiper=%s)\n", name, base_print, piper_print)
                        continue
                    }

                    base = bench_data[base_key]
                    piper = bench_data[piper_key]
                    # convert string values to numbers for arithmetic
                    base_val = base + 0
                    piper_val = piper + 0

                    if (base_val == 0) {
                        printf("  %s: zero baseline MB/s, cannot compute ratio (baseline=%s sshpiper=%s)\n", name, base, piper)
                        continue
                    }

                    ratio = piper_val / base_val * 100
                    printf("  %s: sshpiper %s MB/s vs baseline %s MB/s (%.1f%%)\n", name, piper, base, ratio)
                }
            }
        ' "${bench_output}"

    fi
fi
