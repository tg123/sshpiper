#!/usr/bin/env bash
 
set -o errexit
set -o nounset
set -o pipefail

go mod vendor
 
SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")
REPO_ROOT=$(realpath "${SCRIPT_ROOT}/../../")
CODEGEN_PKG=${REPO_ROOT}/vendor/k8s.io/code-generator
THIS_PKG="github.com/tg123/sshpiper/plugin/kubernetes"
 
source "${CODEGEN_PKG}/kube_codegen.sh"


kube::codegen::gen_helpers \
    --boilerplate /dev/null \
    "${SCRIPT_ROOT}"    

kube::codegen::gen_register \
    --boilerplate /dev/null \
    "${SCRIPT_ROOT}"

kube::codegen::gen_client \
    --with-watch \
    --output-dir "${SCRIPT_ROOT}/generated" \
    --output-pkg "${THIS_PKG}/generated" \
    --boilerplate /dev/null \
    "${SCRIPT_ROOT}/apis"    