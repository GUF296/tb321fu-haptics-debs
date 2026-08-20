#!/bin/bash -p
case $- in
  *p*) ;;
  *) echo 'compatibility-package verification requires privileged Bash mode' >&2; exit 1 ;;
esac
set -euo pipefail

[ "$#" -eq 6 ] || {
  echo 'usage: verify-haptics-compat-package.sh PRIVATE_DEB PUBLIC_DEB PACKAGE VERSION ARCHITECTURE SHA256' >&2
  exit 1
}
archive=$1
public_archive=$2
package=$3
version=$4
architecture=$5
expected_digest=$6
created_public=0
promotion_complete=0
cleanup_partial_promotion() {
  if [ "$created_public" = 1 ] && [ "$promotion_complete" != 1 ]; then
    /usr/bin/rm -f -- "$public_archive"
  fi
}
trap cleanup_partial_promotion EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
[[ $package =~ ^[a-z0-9][a-z0-9+.-]{0,79}$ ]] || exit 1
[[ $version =~ ^[0-9A-Za-z][0-9A-Za-z.+:~-]{0,159}$ ]] || exit 1
[[ $architecture = amd64 || $architecture = all ]] || exit 1
[[ $expected_digest =~ ^[0-9a-f]{64}$ ]] || exit 1
[[ $archive = /* && $public_archive = /* ]] || {
  echo 'compatibility package paths must be absolute' >&2
  exit 1
}
private_parent=${archive%/*}
public_parent=${public_archive%/*}
expected_private_name="${package}_${version}_${architecture}.deb.part"
expected_public_name="${package}_${version}_${architecture}.deb"
[ "${archive##*/}" = "$expected_private_name" ] &&
  [ "${public_archive##*/}" = "$expected_public_name" ] || {
    echo "compatibility package path identity mismatch: $package" >&2
    exit 1
  }
[ "$private_parent" != "$public_parent" ] &&
  [ "$private_parent" = "$(/usr/bin/realpath -e -- "$private_parent")" ] &&
  [ "$public_parent" = "$(/usr/bin/realpath -e -- "$public_parent")" ] || {
    echo "compatibility package directories are not canonical and separate: $package" >&2
    exit 1
  }
current_uid=$(/usr/bin/id -u)
current_gid=$(/usr/bin/id -g)
[ -d "$private_parent" ] && [ ! -L "$private_parent" ] &&
  [ "$(/usr/bin/stat -c '%a:%u:%g' -- "$private_parent")" = \
    "700:$current_uid:$current_gid" ] || {
    echo "compatibility package private directory is unsafe: $package" >&2
    exit 1
  }
[ -d "$public_parent" ] && [ ! -L "$public_parent" ] &&
  [ "$(/usr/bin/stat -c '%a:%u:%g' -- "$public_parent")" = \
    "755:$current_uid:$current_gid" ] || {
    echo "compatibility package public directory is unsafe: $package" >&2
    exit 1
  }
[ "$(/usr/bin/stat -c '%d' -- "$private_parent")" = \
  "$(/usr/bin/stat -c '%d' -- "$public_parent")" ] || {
    echo "compatibility package promotion crosses filesystems: $package" >&2
    exit 1
  }
[ ! -e "$public_archive" ] && [ ! -L "$public_archive" ] || {
  echo "compatibility package public path already exists: $package" >&2
  exit 1
}
[ -f "$archive" ] && [ ! -L "$archive" ] || {
  echo "compatibility package is not a regular file: $package" >&2
  exit 1
}
[ "$(/usr/bin/stat -c '%a:%u:%g:%h' -- "$archive")" = \
  "600:$current_uid:$current_gid:1" ] || {
    echo "compatibility package private file is unsafe: $package" >&2
    exit 1
  }
[ "$(/usr/bin/stat -c '%s' -- "$archive")" -gt 0 ] || {
  echo "compatibility package is empty: $package" >&2
  exit 1
}
[ "$(/usr/bin/stat -c '%s' -- "$archive")" -le 67108864 ] || {
  echo "compatibility package exceeds its size bound: $package" >&2
  exit 1
}
verified_identity=$(/usr/bin/stat -c '%d:%i:%s' -- "$archive")
[ "$(/usr/bin/sha256sum -- "$archive" | /usr/bin/cut -d' ' -f1)" = \
  "$expected_digest" ] || {
  echo "compatibility package digest mismatch: $package" >&2
  exit 1
}
mapfile -t metadata < <(
  /usr/bin/dpkg-deb --show \
    --showformat='${Package}\n${Version}\n${Architecture}\n' "$archive"
)
[ "${#metadata[@]}" -eq 3 ] &&
  [ "${metadata[0]}" = "$package" ] &&
  [ "${metadata[1]}" = "$version" ] &&
  [ "${metadata[2]}" = "$architecture" ] || {
    echo "compatibility package control identity mismatch: $package" >&2
    exit 1
  }
[ "$verified_identity" = "$(/usr/bin/stat -c '%d:%i:%s' -- "$archive")" ] &&
  [ "$(/usr/bin/stat -c '%a:%u:%g:%h' -- "$archive")" = \
    "600:$current_uid:$current_gid:1" ] || {
    echo "compatibility package changed during verification: $package" >&2
    exit 1
  }
/usr/bin/chmod 0644 "$archive"
/usr/bin/ln -- "$archive" "$public_archive"
created_public=1
[ "$verified_identity" = "$(/usr/bin/stat -c '%d:%i:%s' -- "$public_archive")" ] &&
  [ "$(/usr/bin/stat -c '%a:%u:%g:%h' -- "$public_archive")" = \
    "644:$current_uid:$current_gid:2" ] || {
    echo "compatibility package promotion changed the verified inode: $package" >&2
    exit 1
  }
/usr/bin/rm -- "$archive"
[ ! -e "$archive" ] && [ ! -L "$archive" ] &&
  [ "$verified_identity" = "$(/usr/bin/stat -c '%d:%i:%s' -- "$public_archive")" ] &&
  [ "$(/usr/bin/stat -c '%a:%u:%g:%h' -- "$public_archive")" = \
    "644:$current_uid:$current_gid:1" ] || {
    echo "compatibility package promotion did not close atomically: $package" >&2
    exit 1
  }
promotion_complete=1
echo 'HAPTICS_COMPAT_PACKAGE=PASS'
