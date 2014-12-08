#!/bin/bash

if [ -z $GOPATH ]; then
    echo "set go path first"
    exit 1
fi

echo "Using go path $GOPATH"


if [ ! -f $GOPATH/bin/sshpiperd ];then
    go get github.com/tg123/sshpiper/sshpiperd
    go install github.com/tg123/sshpiper/sshpiperd
fi

SSHPIPERD_BIN="$GOPATH/bin/sshpiperd"
BASEDIR="$GOPATH/src/github.com/tg123/sshpiper/sshpiperd/example"

if [ ! -f $BASEDIR/sshpiperd_key ];then
    ssh-keygen -N '' -f $BASEDIR/sshpiperd_key
fi

for u in `find $BASEDIR/workingdir/ -name sshpiper_upstream`; do
    upstream=`cat $u`

    username=`dirname $u`
    username=`basename $username`

    echo "ssh 127.0.0.1 -p 2222 -l $username # connect to $upstream"
done

$SSHPIPERD_BIN -i $BASEDIR/sshpiperd_key -w $BASEDIR/workingdir
