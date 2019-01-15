#!/bin/sh

echo 1
sleep 10 # TODO remove ulgy workaround 
echo 2

/sshpiperd pipe add -n host1 -u host1 --upstream-username root
/sshpiperd pipe add -n host2 -u host2 --upstream-username root
/sshpiperd pipe list


/sshpiperd daemon
