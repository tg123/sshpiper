#!/bin/bash

set -e

for pkg in $(go list ./...); do 
    go test -cover $pkg; 
done

