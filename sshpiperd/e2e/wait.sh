#!/bin/sh

for i in `seq 300`; do
    nc -w 1 -z "$1" "$2"
    if [ $? -eq 0 ]; then
        break
    fi
    sleep 1
done

if [ -n "$3" ]; then 
    sleep $3; 
fi