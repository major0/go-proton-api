#!/bin/sh
set -eu
POSIXLY_CORRECT='no bashing shell'

##
# ${*} = message to print to stderr
# returns: 0
error() {
  : "error(msg='${*}')"
  printf 'error: %s\n' "${*}" >&2
}

##
# ${*} = fatal message
# returns: does not return (exits 1)
die() {
  : "die(msg='${*}')"
  error "${*}"
  exit 1
}

REPO_ROOT="$(cd "$(dirname "${0}")/.." && pwd)"
SPEC_DIR="${REPO_ROOT}/../open-proton-api.git/output"
OAPI_CODEGEN='github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0'
OUTPUT_BASE="${REPO_ROOT}/internal/openapi-client"

##
# finds the latest proton-full-api spec in the output dir
# sets SPEC to the resolved path; dies if not found
# returns: 0
resolve_spec() {
  : 'resolve_spec()'
  SPEC=''
  for f in "${SPEC_DIR}"/proton-full-api-*.json; do
    test -f "${f}" || continue
    SPEC="${f}"
  done
  test -n "${SPEC}" || die "No proton-full-api-*.json found in ${SPEC_DIR}"
  printf 'Using spec: %s\n' "${SPEC}"
}

##
# ${1} = package name (directory name under openapi-client/)
# ${2} = comma-separated tags to include
# returns: 0
generate_package() {
  : "generate_package(pkg='${1}', tags='${2}')"
  PKG_NAME="${1}api"
  PKG_DIR="${OUTPUT_BASE}/${1}"

  mkdir -p "${PKG_DIR}"

  printf 'Generating %s types...\n' "${1}"
  go run "${OAPI_CODEGEN}" \
      --package "${PKG_NAME}" \
      --generate types \
      --include-tags "${2}" \
      -o "${PKG_DIR}/types.gen.go" \
      "${SPEC}"

  printf 'Generating %s client...\n' "${1}"
  go run "${OAPI_CODEGEN}" \
      --package "${PKG_NAME}" \
      --generate client \
      --include-tags "${2}" \
      -o "${PKG_DIR}/client.gen.go" \
      "${SPEC}"

  # Post-process: remove duplicate struct fields caused by camelCase/PascalCase collisions
  if test -f "${PKG_DIR}/types.gen.go"; then
    sed -i \
        -e '/json:"clientUID,omitempty"/d' \
        -e '/json:"currentRevisionId,omitempty"/d' \
        -e '/json:"lastIndex,omitempty"/d' \
        -e '/json:"sessionName,omitempty"/d' \
        -e '/json:"pageSize,omitempty"/d' \
        -e '/json:"nameHashes,omitempty"/d' \
        -e '/json:"email,omitempty"/d' \
        -e '/json:"maxAI,omitempty"/d' \
        -e '/json:"maxLumo,omitempty"/d' \
        -e '/json:"maxSpace,omitempty"/d' \
        -e '/json:"add,omitempty"/d' \
        -e '/json:"remove,omitempty"/d' \
        -e '/form:"Q,omitempty"/d' \
        "${PKG_DIR}/types.gen.go"
  fi
}

##
# generates every service package
# returns: 0
generate_all() {
  : 'generate_all()'
  generate_package 'core'     'account,auth,oauth,core,permissions,groups,members'
  generate_package 'drive'    'shares,volumes,blocks,devices,photos,urls,unauth,entitlements,health,me,migrations,organization,report,sanitization,shared-bookmarks,sharedwithme,user-link-access,checklist,onboarding'
  generate_package 'mail'     'mail'
  generate_package 'calendar' 'calendar'
  generate_package 'contacts' 'contacts'
  generate_package 'domains'  'domains'
  generate_package 'lumo'     'ai'
  generate_package 'meet'     'meet'
  generate_package 'vpn'      'vpn'
}

# --- Main ---

resolve_spec

case "${1:-all}" in
(all)
  generate_all
  ;;
(core)
  generate_package 'core' 'account,auth,oauth,core,permissions,groups,members'
  ;;
(drive)
  generate_package 'drive' 'shares,volumes,blocks,devices,photos,urls,unauth,entitlements,health,me,migrations,organization,report,sanitization,shared-bookmarks,sharedwithme,user-link-access,checklist,onboarding'
  ;;
(mail)
  generate_package 'mail' 'mail'
  ;;
(calendar)
  generate_package 'calendar' 'calendar'
  ;;
(contacts)
  generate_package 'contacts' 'contacts'
  ;;
(domains)
  generate_package 'domains' 'domains'
  ;;
(lumo)
  generate_package 'lumo' 'ai'
  ;;
(meet)
  generate_package 'meet' 'meet'
  ;;
(vpn)
  generate_package 'vpn' 'vpn'
  ;;
(*)
  die "Unknown category: ${1}"
  ;;
esac

printf 'Done.\n'
unset REPO_ROOT SPEC_DIR SPEC OAPI_CODEGEN OUTPUT_BASE
