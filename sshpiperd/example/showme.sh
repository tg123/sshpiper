#!/bin/bash

GOPATH=`go env GOPATH`

if [ ! -f $GOPATH/bin/sshpiperd ] || [ $GOPATH/bin/sshpiperd -ot $GOPATH/src/github.com/tg123/sshpiper ];then
    go get github.com/tg123/sshpiper/sshpiperd
fi

SSHPIPERD_BIN="$GOPATH/bin/sshpiperd"
BASEDIR="$GOPATH/src/github.com/tg123/sshpiper/sshpiperd/example"

if [ ! -f $BASEDIR/sshpiperd_key ];then
    $SSHPIPERD_BIN genkey > $BASEDIR/sshpiperd_key
fi



$SSHPIPERD_BIN pipe --upstream-workingdir=$BASEDIR/workingdir add -n github -u github.com --upstream-user git 2>/dev/null
$SSHPIPERD_BIN pipe --upstream-workingdir=$BASEDIR/workingdir add -n gitlab -u gitlab.com --upstream-user git 2>/dev/null
$SSHPIPERD_BIN pipe --upstream-workingdir=$BASEDIR/workingdir add -n bitbucket -u bitbucket.org --upstream-user git 2>/dev/null

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

#for u in `find $BASEDIR/workingdir/ -name sshpiper_upstream`; do
#    chmod 400 $u
#    upstream=`cat $u`
#
#    username=`dirname $u`
#    username=`basename $username`
#
#    echo "ssh 127.0.0.1 -p 2222 -l $username # connect to $upstream"
#done

$SSHPIPERD_BIN daemon -i $BASEDIR/sshpiperd_key --upstream-workingdir=$BASEDIR/workingdir
