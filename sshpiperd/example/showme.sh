#!/bin/bash

set -e

CURRENT_DIR=$(dirname $(realpath $0))
SSHPIPERD_SRC=$CURRENT_DIR/..
BASEDIR=$(mktemp -d)
go build -o $BASEDIR/sshpiperd $SSHPIPERD_SRC

SSHPIPERD_BIN="$BASEDIR/sshpiperd"

if [ ! -f $BASEDIR/sshpiperd_key ];then
    $SSHPIPERD_BIN genkey > $BASEDIR/sshpiperd_key
fi

$SSHPIPERD_BIN pipe --upstream-workingdir=$BASEDIR/workingdir add -n github -u github.com --upstream-username git 
$SSHPIPERD_BIN pipe --upstream-workingdir=$BASEDIR/workingdir add -n gitlab -u gitlab.com --upstream-username git 
$SSHPIPERD_BIN pipe --upstream-workingdir=$BASEDIR/workingdir add -n bitbucket -u bitbucket.org --upstream-username git

IFS="
"

echo "#### CURRENT PIPES"
echo "# "
echo "# test using ssh 127.0.0.1 -p 2222 -l username"
echo 

for p in `$SSHPIPERD_BIN pipe --upstream-workingdir=$BASEDIR/workingdir list`; do
    user=`echo $p | cut -f 1 -d ' '`
    echo "$p # ssh 127.0.0.1 -p 2222 -l $user"
done

echo 
echo "#### "
echo "#### git clone example"

echo "# cp ~/.ssh/id_rsa $BASEDIR/workingdir/github/"
echo "# ssh-keygen -y -f ~/.ssh/id_rsa > $BASEDIR/workingdir/github/authorized_keys"
echo "# chmod 400 $BASEDIR/workingdir/github/authorized_keys"
echo "git clone git clone ssh://github@127.0.0.1:2222/[youruser]/[yourproj]# e.g. ssh://github@127.0.0.1:2222/tg123/sshpiper"

echo "#### "
echo "Starting piper"

$SSHPIPERD_BIN daemon -i $BASEDIR/sshpiperd_key --upstream-workingdir=$BASEDIR/workingdir
