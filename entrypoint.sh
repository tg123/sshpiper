#!/bin/sh
set -eo pipefail

PLUGIN=${PLUGIN:-workingdir}
export SSHPIPERD_SERVER_KEY_GENERATE_MODE=${SSHPIPERD_SERVER_KEY_GENERATE_MODE:-notexist}

/sshpiperd/sshpiperd "${@:-/sshpiperd/plugins/$PLUGIN}"