#!/bin/bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 HAPTICS-BUILD-PACKAGES.tsv" >&2
  exit 2
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PACKAGE_LOCK=$1
PACKAGE_VERIFIER="$SCRIPT_DIR/verify-haptics-build-packages.py"
COMPILER=/usr/bin/aarch64-linux-gnu-gcc-13

fail() {
  printf 'test failure: %s\n' "$*" >&2
  exit 1
}

verify_lock_line() {
  local lock=$1 expected=$2

  [ "$(/usr/bin/grep -Fxc -- "$expected" "$lock")" -eq 1 ] ||
    return 1
}

verify_cross_link_lock() {
  local lock=$1

  verify_lock_line "$lock" $'package\tlibc6-arm64-cross\tall\t2.39-0ubuntu8cross1\tclosure' &&
    verify_lock_line "$lock" $'package\tlibc6-dev-arm64-cross\tall\t2.39-0ubuntu8cross1\trequested' &&
    verify_lock_line "$lock" $'package\tlinux-libc-dev-arm64-cross\tall\t6.8.0-25.25cross1\tclosure'
}

verify_installed_package() {
  local name=$1 version=$2 architecture=$3 actual

  actual=$(/usr/bin/dpkg-query -W \
    -f='${Status}\t${Version}\t${Architecture}\n' -- "$name") ||
    fail "cannot query required cross-link package: $name"
  [ "$actual" = $'install ok installed\t'"$version"$'\t'"$architecture" ] ||
    fail "required cross-link package state differs: $name"
}

verify_owned_regular_file() {
  local package=$1 path=$2 owner state

  owner=$(/usr/bin/dpkg-query -S -- "$path") ||
    fail "cannot query cross-link package member: $path"
  [ "$owner" = "$package: $path" ] ||
    fail "cross-link package member has an unexpected owner: $path"
  [ -f "$path" ] && [ ! -L "$path" ] ||
    fail "cross-link package member is not a regular file: $path"
  state=$(/usr/bin/stat -c '%a:%u:%g:%h' -- "$path") ||
    fail "cannot inspect cross-link package member: $path"
  [ "$state" = 644:0:0:1 ] ||
    fail "cross-link package member metadata differs: $path"
}

cc_can_link() {
  /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C LC_ALL=C TZ=UTC HOME=/nonexistent TMPDIR=/tmp \
    "$COMPILER" "$@" \
    -Werror -Wl,--fatal-warnings -x c - -o /dev/null >/dev/null 2>&1 <<'EOF_C'
#include <stdio.h>
int main(void)
{
	printf("\n");
	return 0;
}
EOF_C
}

/usr/bin/python3 -I -B "$PACKAGE_VERIFIER" "$PACKAGE_LOCK" >/dev/null
verify_cross_link_lock "$PACKAGE_LOCK" ||
  fail "package lock omits the exact cross-link development closure"

fixture_dir=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/tb321fu-cross-link.XXXXXX")
cleanup() { /usr/bin/rm -rf -- "$fixture_dir"; }
trap cleanup EXIT

/usr/bin/grep -Fv -- $'package\tlibc6-dev-arm64-cross\t' \
  "$PACKAGE_LOCK" > "$fixture_dir/no-libc-dev.tsv"
if verify_cross_link_lock "$fixture_dir/no-libc-dev.tsv"; then
  fail "cross-link lock fixture accepted a missing libc development root"
fi
/usr/bin/grep -Fv -- $'package\tlinux-libc-dev-arm64-cross\t' \
  "$PACKAGE_LOCK" > "$fixture_dir/no-linux-libc-dev.tsv"
if verify_cross_link_lock "$fixture_dir/no-linux-libc-dev.tsv"; then
  fail "cross-link lock fixture accepted a missing Linux UAPI header closure"
fi

verify_installed_package libc6-arm64-cross 2.39-0ubuntu8cross1 all
verify_installed_package libc6-dev-arm64-cross 2.39-0ubuntu8cross1 all
verify_installed_package linux-libc-dev-arm64-cross 6.8.0-25.25cross1 all

verify_owned_regular_file libc6-dev-arm64-cross \
  /usr/aarch64-linux-gnu/include/stdio.h
verify_owned_regular_file libc6-dev-arm64-cross \
  /usr/aarch64-linux-gnu/lib/Scrt1.o
verify_owned_regular_file linux-libc-dev-arm64-cross \
  /usr/aarch64-linux-gnu/include/linux/version.h

[ -f "$COMPILER" ] && [ -x "$COMPILER" ] && [ ! -L "$COMPILER" ] ||
  fail "cross compiler is not a regular executable: $COMPILER"
cc_can_link || fail "locked cross-libc development closure cannot link userspace C"
if cc_can_link -nostdinc; then
  fail "CC_CAN_LINK probe unexpectedly passed without development headers"
fi
if cc_can_link -nostartfiles -nodefaultlibs; then
  fail "CC_CAN_LINK probe unexpectedly passed without startup objects and libc"
fi

printf 'HAPTICS_CC_CAN_LINK_CLOSURE=PASS\n'
