#!/usr/bin/env bash
set -euo pipefail

image=${1:-sshpiper-test-image}
containers=()

cleanup() {
    for container in "${containers[@]}"; do
        docker logs "$container" || true
        docker rm --force "$container" >/dev/null || true
    done
}
trap cleanup EXIT

start_container() {
    container=$(docker run --detach "$image" "$@")
    containers+=("$container")
}

wait_for() {
    for _ in {1..100}; do
        if "$@" >/dev/null 2>&1; then
            return
        fi
        sleep 0.1
    done
    echo "Timed out waiting for: $*" >&2
    "$@"
    return 1
}

daemon_ready() {
    docker logs "$container" 2>&1 | grep -q 'sshpiperd is listening'
}

expect_exit() {
    local actual
    actual=$(timeout 15s docker wait "$container")
    if [[ "$actual" != "$1" ]]; then
        echo "Expected container exit status $1, got $actual" >&2
        return 1
    fi
}

# The plugin keeps its PID while an intermediate shell orphans a long-lived
# helper. Observe adoption before killing the helper so a zombie cannot pass.
plugin_script=$(cat <<'PLUGIN'
echo $$ > /etc/ssh/plugin.pid
sh -ec 'sleep 600 </dev/null >/dev/null 2>&1 & echo $! > /etc/ssh/orphan.pid'
exec /sshpiperd/plugins/workingdir
PLUGIN
)
start_container /bin/sh -ec "$plugin_script"
wait_for daemon_ready
wait_for docker exec "$container" /bin/sh -ec '
    test "$(readlink /proc/1/exe)" = /sbin/tini
    orphan=$(cat /etc/ssh/orphan.pid)
    test "$(sed -n "s/^PPid:[[:space:]]*//p" "/proc/$orphan/status")" = 1
    plugin=$(cat /etc/ssh/plugin.pid)
    parent=$(sed -n "s/^PPid:[[:space:]]*//p" "/proc/$plugin/status")
    test "$(readlink "/proc/$parent/exe")" = /sshpiperd/sshpiperd
'
docker exec "$container" /bin/sh -ec 'kill "$(cat /etc/ssh/orphan.pid)"'
wait_for docker exec "$container" /bin/sh -ec '
    test ! -e "/proc/$(cat /etc/ssh/orphan.pid)"
'

# Tokio must still observe its own child's termination, without Tini stealing
# the wait status or allowing an adopted child's exit to stop the daemon.
docker exec "$container" /bin/sh -ec 'kill "$(cat /etc/ssh/plugin.pid)"'
expect_exit 1
docker logs "$container" 2>&1 | grep -q 'plugin /bin/sh exited:'

for signal in TERM INT; do
    start_container /sshpiperd/plugins/workingdir
    wait_for daemon_ready
    docker kill --signal "$signal" "$container" >/dev/null
    expect_exit 0
done

start_container --port not-a-number
expect_exit 2
echo "Container init reaping, plugin waits, signals, and exit statuses passed"
