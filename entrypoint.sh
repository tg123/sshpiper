#!/bin/sh
set -eo pipefail

PLUGIN=${PLUGIN:-workingdir}
export SSHPIPERD_SERVER_KEY_GENERATE_MODE=${SSHPIPERD_SERVER_KEY_GENERATE_MODE:-notexist}

exec /sshpiperd/sshpiperd "${@:-/sshpiperd/plugins/$PLUGIN}"
