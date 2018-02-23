#!/bin/bash

set -e

pkgs="./libpiper/... ./sshpiperd/..."

gofmt -s -l libpiper sshpiperd
go vet $pkgs
golint $pkgs
