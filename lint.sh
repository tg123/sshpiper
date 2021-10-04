#!/bin/bash

set -e

gofmt -s -l libpiper sshpiperd

go vet ./...
go fix ./...

ineffassign ./...
