#!/bin/bash
set -e

VER_FILE=".golangssh_lastpick"
LAST_VER=`cat $VER_FILE`

git fetch https://github.com/golang/crypto.git

for v in `git log --reverse --format=%H $LAST_VER..FETCH_HEAD ssh`; do
    git cherry-pick $v
    echo $v > $VER_FILE
done
