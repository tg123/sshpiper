#!/bin/sh

if [ ! -z $WAIT_HOST ]; then
    /wait.sh $WAIT_HOST $WAIT_PORT $EXTRA_WAIT
fi

/sshpiperd pipe add -n host1 -u host1 --upstream-username root
/sshpiperd pipe add -n host2 -u host2 --upstream-username root
/sshpiperd pipe list


/sshpiperd daemon
