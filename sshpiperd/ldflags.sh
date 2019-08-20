#!/bin/sh

cd $GOPATH/src/github.com/tg123/sshpiper

githash=`git log --pretty=format:%h,%ad --name-only --date=short . | head -n 1`
ver=`cat ver`

echo "-X main.version=$ver -X main.githash=$githash"
