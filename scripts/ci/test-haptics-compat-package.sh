#!/bin/bash -p
set -euo pipefail
umask 077

SCRIPT_PATH=$(/usr/bin/realpath -e -- "${BASH_SOURCE[0]}")
SCRIPT_DIR=${SCRIPT_PATH%/*}
VERIFIER="$SCRIPT_DIR/verify-haptics-compat-package.sh"
tmp=$(/usr/bin/mktemp -d /tmp/tb321fu-haptics-compat-test.XXXXXX)
cleanup() {
  /usr/bin/rm -rf -- "$tmp"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

package_root="$tmp/package"
/usr/bin/mkdir -p "$package_root/DEBIAN" "$tmp/private" "$tmp/public"
/usr/bin/chmod 0755 "$tmp" "$tmp/public"
/usr/bin/chmod 0700 "$tmp/private"
/usr/bin/chmod 0755 "$package_root/DEBIAN"
{
  echo 'Package: fixture-package'
  echo 'Version: 1.2.3'
  echo 'Architecture: amd64'
  echo 'Maintainer: TB321FU fixture <noreply@example.invalid>'
  echo 'Description: compatibility package verifier fixture'
} > "$package_root/DEBIAN/control"
/usr/bin/chmod 0644 "$package_root/DEBIAN/control"
/usr/bin/dpkg-deb --build --root-owner-group \
  "$package_root" "$tmp/private/fixture-package_1.2.3_amd64.deb.part" >/dev/null
private_archive="$tmp/private/fixture-package_1.2.3_amd64.deb.part"
public_archive="$tmp/public/fixture-package_1.2.3_amd64.deb"
/usr/bin/chmod 0600 "$private_archive"
digest=$(/usr/bin/sha256sum -- "$private_archive" | /usr/bin/cut -d' ' -f1)
private_identity=$(/usr/bin/stat -c '%d:%i:%s' -- "$private_archive")
/bin/bash -p "$VERIFIER" "$private_archive" "$public_archive" \
  fixture-package 1.2.3 amd64 "$digest" >/dev/null
[ ! -e "$private_archive" ] && [ ! -L "$private_archive" ] || {
  echo 'compatibility verifier retained its private archive after promotion' >&2
  exit 1
}
[ -f "$public_archive" ] && [ ! -L "$public_archive" ] || {
  echo 'compatibility verifier did not create a regular public archive' >&2
  exit 1
}
[ "$private_identity" = "$(/usr/bin/stat -c '%d:%i:%s' -- "$public_archive")" ] || {
  echo 'compatibility verifier did not preserve the verified inode' >&2
  exit 1
}
[ "$(/usr/bin/stat -c '%a:%u:%g:%h' -- "$public_archive")" = \
  "644:$(/usr/bin/id -u):$(/usr/bin/id -g):1" ] || {
  echo 'compatibility verifier published unsafe ownership, mode, or links' >&2
  exit 1
}

for field in package version architecture digest; do
  private_case="$tmp/private/fixture-package_1.2.3_amd64.deb.part"
  /usr/bin/cp -- "$public_archive" "$private_case"
  /usr/bin/chmod 0600 "$private_case"
  case "$field" in
    package) arguments=(other-package 1.2.3 amd64 "$digest") ;;
    version) arguments=(fixture-package 9.9.9 amd64 "$digest") ;;
    architecture) arguments=(fixture-package 1.2.3 all "$digest") ;;
    digest) arguments=(fixture-package 1.2.3 amd64 "$(printf '0%.0s' {1..64})") ;;
  esac
  case_public="$tmp/public-$field"
  /usr/bin/mkdir -- "$case_public"
  /usr/bin/chmod 0755 "$case_public"
  public_case="$case_public/${arguments[0]}_${arguments[1]}_${arguments[2]}.deb"
  if /bin/bash -p "$VERIFIER" "$private_case" "$public_case" \
    "${arguments[@]}" >/dev/null 2>&1; then
    echo "compatibility verifier accepted wrong $field" >&2
    exit 1
  fi
  [ ! -e "$public_case" ] && [ ! -L "$public_case" ] || {
    echo "compatibility verifier published a wrong-$field archive" >&2
    exit 1
  }
  /usr/bin/rm -f -- "$private_case"
done

/usr/bin/ln -s "$public_archive" "$tmp/private/fixture-package_1.2.3_amd64.deb.part"
/usr/bin/mkdir -- "$tmp/public-symlink"
/usr/bin/chmod 0755 "$tmp/public-symlink"
if /bin/bash -p "$VERIFIER" \
  "$tmp/private/fixture-package_1.2.3_amd64.deb.part" \
  "$tmp/public-symlink/fixture-package_1.2.3_amd64.deb" \
  fixture-package 1.2.3 amd64 "$digest" \
  >/dev/null 2>&1; then
  echo 'compatibility verifier accepted a symlink' >&2
  exit 1
fi
/usr/bin/rm -- "$tmp/private/fixture-package_1.2.3_amd64.deb.part"

/usr/bin/cp -- "$public_archive" "$tmp/private/fixture-package_1.2.3_amd64.deb.part"
/usr/bin/chmod 0600 "$tmp/private/fixture-package_1.2.3_amd64.deb.part"
/usr/bin/ln -- "$tmp/private/fixture-package_1.2.3_amd64.deb.part" \
  "$tmp/private/second-link.deb"
/usr/bin/mkdir -- "$tmp/public-hardlink"
/usr/bin/chmod 0755 "$tmp/public-hardlink"
if /bin/bash -p "$VERIFIER" \
  "$tmp/private/fixture-package_1.2.3_amd64.deb.part" \
  "$tmp/public-hardlink/fixture-package_1.2.3_amd64.deb" \
  fixture-package 1.2.3 amd64 "$digest" \
  >/dev/null 2>&1; then
  echo 'compatibility verifier accepted a multiply linked private archive' >&2
  exit 1
fi
/usr/bin/rm -- "$tmp/private/fixture-package_1.2.3_amd64.deb.part" \
  "$tmp/private/second-link.deb"

/usr/bin/cp -- "$public_archive" "$tmp/private/fixture-package_1.2.3_amd64.deb.part"
/usr/bin/chmod 0600 "$tmp/private/fixture-package_1.2.3_amd64.deb.part"
/usr/bin/mkdir -- "$tmp/public-writable"
/usr/bin/chmod 0775 "$tmp/public-writable"
if /bin/bash -p "$VERIFIER" \
  "$tmp/private/fixture-package_1.2.3_amd64.deb.part" \
  "$tmp/public-writable/fixture-package_1.2.3_amd64.deb" \
  fixture-package 1.2.3 amd64 "$digest" \
  >/dev/null 2>&1; then
  echo 'compatibility verifier accepted a group-writable public directory' >&2
  exit 1
fi
/usr/bin/rm -- "$tmp/private/fixture-package_1.2.3_amd64.deb.part"

/usr/bin/cp -- "$public_archive" "$tmp/private/fixture-package_1.2.3_amd64.deb.part"
/usr/bin/chmod 0600 "$tmp/private/fixture-package_1.2.3_amd64.deb.part"
/usr/bin/mkdir -- "$tmp/public-existing"
/usr/bin/chmod 0755 "$tmp/public-existing"
: > "$tmp/public-existing/fixture-package_1.2.3_amd64.deb"
if /bin/bash -p "$VERIFIER" \
  "$tmp/private/fixture-package_1.2.3_amd64.deb.part" \
  "$tmp/public-existing/fixture-package_1.2.3_amd64.deb" \
  fixture-package 1.2.3 amd64 "$digest" \
  >/dev/null 2>&1; then
  echo 'compatibility verifier replaced an existing public archive' >&2
  exit 1
fi
[ -s "$tmp/private/fixture-package_1.2.3_amd64.deb.part" ] &&
  [ ! -s "$tmp/public-existing/fixture-package_1.2.3_amd64.deb" ] || {
    echo 'compatibility verifier changed state after no-clobber rejection' >&2
    exit 1
  }
echo 'HAPTICS_COMPAT_PACKAGE_FIXTURE=PASS'
