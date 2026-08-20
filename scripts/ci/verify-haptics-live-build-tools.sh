#!/bin/bash -p
clean_environment=1
[ "${HAPTICS_LIVE_TOOLS_CLEAN_ENV:-}" = 1 ] &&
  [ "${PATH:-}" = /usr/sbin:/usr/bin:/sbin:/bin ] &&
  [ "${LANG:-}" = C ] && [ "${LC_ALL:-}" = C ] &&
  [ "${TZ:-}" = UTC ] && [ "${HOME:-}" = /nonexistent ] &&
  [ "${TMPDIR:-}" = /tmp ] || clean_environment=0
while IFS= read -r -d '' entry; do
  name=${entry%%=*}
  case "$name" in
    PATH|LANG|LC_ALL|TZ|HOME|TMPDIR|HAPTICS_LIVE_TOOLS_CLEAN_ENV|PWD|SHLVL|_) ;;
    *) clean_environment=0 ;;
  esac
done < <(/usr/bin/env -0)
if [ "$clean_environment" != 1 ]; then
  script_path=$(/usr/bin/realpath -e -- "$0") || exit 1
  exec /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C LC_ALL=C TZ=UTC HOME=/nonexistent TMPDIR=/tmp \
    HAPTICS_LIVE_TOOLS_CLEAN_ENV=1 \
    /bin/bash -p "$script_path" "$@"
fi
case $- in
  *p*) ;;
  *) echo 'live build-tool verification requires privileged Bash mode' >&2; exit 1 ;;
esac
set -euo pipefail
umask 077

SCRIPT_PATH=$(/usr/bin/realpath -e -- "${BASH_SOURCE[0]}")
SCRIPT_DIR=${SCRIPT_PATH%/*}
. "$SCRIPT_DIR/common.sh"
. "$SCRIPT_DIR/haptics-build-environment.sh"

verify_manifest() {
  local actual=$1 expected=$2 reference=$3
  local expected_digest actual_digest count

  /usr/bin/python3 -I -B "$SCRIPT_DIR/verify-haptics-release-reference.py" \
    "$reference" >/dev/null
  for manifest in "$actual" "$expected"; do
    [ -f "$manifest" ] && [ ! -L "$manifest" ] ||
      ci_die "build-tools manifest is not a regular file: $manifest"
    [ "$(/usr/bin/stat -c '%a' -- "$manifest")" = 644 ] ||
      ci_die "build-tools manifest mode must be 0644: $manifest"
  done
  count=$(/usr/bin/awk -F '\t' \
    '$1 == "build-tools-manifest-sha256" { count++ } END { print count + 0 }' \
    "$reference")
  [ "$count" -eq 1 ] || ci_die "release reference must contain one build-tools digest"
  expected_digest=$(/usr/bin/awk -F '\t' \
    '$1 == "build-tools-manifest-sha256" { print $2 }' "$reference")
  [[ $expected_digest =~ ^[0-9a-f]{64}$ ]] ||
    ci_die "release reference has an invalid build-tools digest"
  [ "$(/usr/bin/sha256sum -- "$expected" | /usr/bin/cut -d' ' -f1)" = \
      "$expected_digest" ] ||
    ci_die "committed build-tools reference digest mismatch"
  actual_digest=$(/usr/bin/sha256sum -- "$actual" | /usr/bin/cut -d' ' -f1)
  [ "$actual_digest" = "$expected_digest" ] ||
    ci_die "live build-tools manifest digest differs from A12"
  /usr/bin/cmp -s -- "$actual" "$expected" ||
    ci_die "live build-tools manifest bytes differ from A12"
}

if [ "${1:-}" = --verify-manifest ]; then
  [ "$#" -eq 4 ] ||
    ci_die "usage: verify-haptics-live-build-tools.sh --verify-manifest ACTUAL EXPECTED REFERENCE"
  verify_manifest "$2" "$3" "$4"
  echo 'HAPTICS_LIVE_BUILD_TOOLS=PASS'
  exit 0
fi

[ "$#" -eq 2 ] ||
  ci_die "usage: verify-haptics-live-build-tools.sh EXPECTED_MANIFEST RELEASE_REFERENCE"
expected_manifest=$(/usr/bin/realpath -e -- "$1") ||
  ci_die "cannot resolve committed build-tools reference"
release_reference=$(/usr/bin/realpath -e -- "$2") ||
  ci_die "cannot resolve haptics release reference"
tmp_dir=$(/usr/bin/mktemp -d /tmp/tb321fu-haptics-live-tools.XXXXXX)
tmp_manifest="$tmp_dir/HAPTICS-BUILD-TOOLS.tsv"
cleanup() {
  /usr/bin/rm -rf -- "$tmp_dir"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

haptics_capture_build_tools
haptics_write_build_tools_manifest "$tmp_manifest"
verify_manifest "$tmp_manifest" "$expected_manifest" "$release_reference"
echo 'HAPTICS_LIVE_BUILD_TOOLS=PASS'
