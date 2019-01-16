#!/bin/sh

for i in `seq 300`; do
    nc -w 1 -z "$1" "$2" >/dev/null 2>&1
    nc -w 1 -z "$1" "$2"
    if [ $? -eq 0 ]; then
        break
    fi
    sleep 1
done
