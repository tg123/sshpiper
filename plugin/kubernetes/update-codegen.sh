#!/usr/bin/env bash
 
set -o errexit
set -o nounset
set -o pipefail

go mod vendor
 
SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")
REPO_ROOT=$(realpath "${SCRIPT_ROOT}/../../")
CODEGEN_PKG=${REPO_ROOT}/vendor/k8s.io/code-generator
 
# generate the code with:
# --output-base    because this script should also be able to run inside the vendor dir of
#                  k8s.io/kubernetes. The output-base is needed for the generators to output into the vendor dir
#                  instead of the $GOPATH directly. For normal projects this can be dropped.
# generators deepcopy,client,informer,lister
chmod +x "${CODEGEN_PKG}"/kube_codegen.sh
"${CODEGEN_PKG}"/kube_codegen.sh \
  "deepcopy,client,lister" \
  github.com/tg123/sshpiper/plugin/kubernetes/generated \
  github.com/tg123/sshpiper/plugin/kubernetes/apis \
  sshpiper:v1beta1 \
  --go-header-file /dev/null \
  --trim-path-prefix github.com/tg123/sshpiper/plugin/kubernetes/
 
