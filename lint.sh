#!/bin/bash

set -e

pkgs="./libpiper/... ./sshpiperd/..."

gofmt -s -l libpiper sshpiperd

go vet ./...
go fix ./...

for p in $pkgs; do
    golint $p
done

ineffassign ./...
