#!/bin/bash -p
clean_environment=1
[ "${HAPTICS_DPKG_HOST_TEST_CLEAN_ENV:-}" = 1 ] &&
  [ "${PATH:-}" = /usr/sbin:/usr/bin:/sbin:/bin ] &&
  [ "${LANG:-}" = C ] && [ "${LC_ALL:-}" = C ] &&
  [ "${TZ:-}" = UTC ] && [ "${HOME:-}" = /root ] &&
  [ "${TMPDIR:-}" = /tmp ] || clean_environment=0
while IFS= read -r -d '' entry; do
  name=${entry%%=*}
  case "$name" in
    PATH|LANG|LC_ALL|TZ|HOME|TMPDIR|HAPTICS_DPKG_HOST_TEST_CLEAN_ENV|PWD|SHLVL|_) ;;
    *) clean_environment=0 ;;
  esac
done < <(/usr/bin/env -0)
if [ "$clean_environment" != 1 ]; then
  script_path=$(/usr/bin/realpath -e -- "$0") || exit 1
  exec /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C LC_ALL=C TZ=UTC HOME=/root TMPDIR=/tmp \
    HAPTICS_DPKG_HOST_TEST_CLEAN_ENV=1 \
    /bin/bash -p "$script_path" "$@"
fi
case $- in
  *p*) ;;
  *) echo 'host dpkg rejection fixture requires privileged Bash mode' >&2; exit 1 ;;
esac
set -euo pipefail
umask 077

[ "$#" -eq 1 ] || {
  echo 'usage: test-haptics-dpkg-host-rejection.sh PACKAGE_LOCK' >&2
  exit 1
}
[ "$(/usr/bin/id -u)" -eq 0 ] || {
  echo 'host dpkg rejection fixture must run as root' >&2
  exit 1
}
SCRIPT_PATH=$(/usr/bin/realpath -e -- "${BASH_SOURCE[0]}")
SCRIPT_DIR=${SCRIPT_PATH%/*}
[ -f "$1" ] && [ ! -L "$1" ] || {
  echo 'host dpkg rejection fixture requires a regular package lock' >&2
  exit 1
}
PACKAGE_LOCK=$(/usr/bin/realpath -e -- "$1")
PACKAGE_VERIFIER="$SCRIPT_DIR/verify-haptics-build-packages.py"
DPKG_CONFIG_VERIFIER="$SCRIPT_DIR/verify-haptics-dpkg-configuration.py"
INSTALLER="$SCRIPT_DIR/install-haptics-build-dependencies.sh"
work_dir=$(/usr/bin/mktemp -d /tmp/tb321fu-haptics-dpkg-host-test.XXXXXX)
hostile_part=/etc/dpkg/dpkg.cfg.d/zz-tb321fu-haptics-hostile-fixture
canary="$work_dir/hook-ran"
hostile_created=0
host_baseline_valid=1
cleanup() {
  if [ "$hostile_created" = 1 ]; then
    /usr/bin/rm -f -- "$hostile_part"
  fi
  /usr/bin/rm -rf -- "$work_dir"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ ! -e "$hostile_part" ] && [ ! -L "$hostile_part" ] || {
  echo 'host dpkg rejection fixture path already exists' >&2
  exit 1
}
if ! /usr/bin/python3 -I -B "$DPKG_CONFIG_VERIFIER" \
  --expected-owner 0 --expected-group 0 /etc/dpkg /root >/dev/null 2>&1; then
  host_baseline_valid=0
fi
before_state="$work_dir/package-state.before.tsv"
HOME=/root /usr/bin/python3 -I -B "$PACKAGE_VERIFIER" \
  --capture-system-state "$PACKAGE_LOCK" > "$before_state"
/usr/bin/chmod 0600 "$before_state"
before_status=$(/usr/bin/sha256sum -- /var/lib/dpkg/status | /usr/bin/cut -d' ' -f1)

{
  printf 'pre-invoke=/usr/bin/touch %s\n' "$canary"
  echo 'path-exclude=/usr/bin/getconf'
  printf 'status-logger=/usr/bin/tee %s\n' "$canary"
} > "$hostile_part"
/usr/bin/chmod 0644 "$hostile_part"
hostile_created=1
if /usr/bin/python3 -I -B "$DPKG_CONFIG_VERIFIER" \
  --expected-owner 0 --expected-group 0 /etc/dpkg /root >/dev/null 2>&1; then
  echo 'native dpkg verifier accepted the hostile configuration part' >&2
  exit 1
fi
if ! /bin/bash -p "$INSTALLER" --check-dpkg-isolation >/dev/null 2>&1; then
  echo 'dependency installer failed while using its isolated dpkg configuration' >&2
  exit 1
fi
[ ! -e "$canary" ] && [ ! -L "$canary" ] || {
  echo 'native dpkg configuration hook executed during rejection fixture' >&2
  exit 1
}
/usr/bin/rm -- "$hostile_part"
hostile_created=0

if [ "$host_baseline_valid" = 1 ]; then
  /usr/bin/python3 -I -B "$DPKG_CONFIG_VERIFIER" \
    --expected-owner 0 --expected-group 0 /etc/dpkg /root >/dev/null
fi
after_state="$work_dir/package-state.after.tsv"
HOME=/root /usr/bin/python3 -I -B "$PACKAGE_VERIFIER" \
  --capture-system-state "$PACKAGE_LOCK" > "$after_state"
/usr/bin/chmod 0600 "$after_state"
/usr/bin/cmp -s -- "$before_state" "$after_state" || {
  echo 'host package state changed during dpkg rejection fixture' >&2
  exit 1
}
after_status=$(/usr/bin/sha256sum -- /var/lib/dpkg/status | /usr/bin/cut -d' ' -f1)
[ "$before_status" = "$after_status" ] || {
  echo 'dpkg status database changed during rejection fixture' >&2
  exit 1
}
echo 'HAPTICS_DPKG_HOST_REJECTION_FIXTURE=PASS'
