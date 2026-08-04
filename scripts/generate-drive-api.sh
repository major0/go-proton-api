#!/bin/sh
set -eu
POSIXLY_CORRECT='no bashing shell'

##
# $* = message to print to stderr
# returns 0
error() {
  : "error(msg='${*}')"
  echo "error: ${*}" >&2
}

##
# $* = fatal message
# returns: does not return (exits 1)
die() {
  : "die(msg='${*}')"
  error "${*}"
  exit 1
}

REPO_ROOT="$(cd "$(dirname "${0}")/.." && pwd)"
SPEC="${REPO_ROOT}/../open-proton-api.git/output/proton-drive-api-2026080303.json"
OAPI_CODEGEN='github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0'

test -f "${SPEC}" || die "OpenAPI spec not found at ${SPEC}"

cd "${REPO_ROOT}"

echo 'Generating types...'
go run "${OAPI_CODEGEN}" \
    --config internal/openapi-client/codegen-types.yaml \
    "${SPEC}"

echo 'Generating client...'
go run "${OAPI_CODEGEN}" \
    --config internal/openapi-client/codegen-client.yaml \
    "${SPEC}"

# Post-process: remove duplicate struct fields caused by camelCase/PascalCase
# collisions in the OpenAPI spec (oapi-codegen maps both to the same Go name).
sed -i \
    -e '/json:"clientUID,omitempty"/d' \
    -e '/json:"currentRevisionId,omitempty"/d' \
    -e '/json:"lastIndex,omitempty"/d' \
    -e '/json:"sessionName,omitempty"/d' \
    -e '/json:"pageSize,omitempty"/d' \
    -e '/json:"nameHashes,omitempty"/d' \
    internal/openapi-client/types.gen.go

echo 'Done.'

unset REPO_ROOT SPEC OAPI_CODEGEN
