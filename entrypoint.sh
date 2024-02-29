#!/bin/sh
set -eo pipefail

PLUGIN=${PLUGIN:-workingdir}
export SSHPIPERD_SERVER_KEY_GENERATE_MODE=${SSHPIPERD_SERVER_KEY_GENERATE_MODE:-notexist}

if [ $# -eq 0 ]; then
    # $PLUGIN can contain a comma/space separated list of plugins
    # to load (e.g., PLUGIN="kubernetes,failtoban")
    PLUGINS=''
    for P in $(echo "$PLUGIN" | tr ',;`$' ' '); do
        PLUGINS="${PLUGINS}/sshpiperd/plugins/${P} -- "
    done

    exec /sshpiperd/sshpiperd ${PLUGINS}
else
    exec /sshpiperd/sshpiperd "${@}"
fi
