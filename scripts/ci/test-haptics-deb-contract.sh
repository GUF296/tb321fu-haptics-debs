#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
verifier="$SCRIPT_DIR/verify-haptics-deb.sh"
. "$SCRIPT_DIR/haptics-maintainer-scripts.sh"
kernel_release=test-kernel

tmp=$(mktemp -d "${TMPDIR:-/tmp}/tb321fu-haptics-deb-contract.XXXXXX")
cleanup() { rm -rf -- "$tmp"; }
trap cleanup EXIT

fail() {
  printf 'test failure: %s\n' "$*" >&2
  exit 1
}

require_failure() {
  local expected=$1
  shift
  local output status

  set +e
  output=$("$@" 2>&1)
  status=$?
  set -e
  [ "$status" -ne 0 ] || fail "malformed DEB fixture unexpectedly passed"
  grep -Fq -- "$expected" <<<"$output" ||
    fail "malformed DEB fixture failed at the wrong boundary: $output"
}

create_package_tree() {
  local root=$1

  install -d -m 0755 \
    "$root/DEBIAN" \
    "$root/etc/skel/.config" \
    "$root/usr/bin" \
    "$root/usr/lib/firmware" \
    "$root/usr/lib/modules/$kernel_release/extra" \
    "$root/usr/lib/systemd/system" \
    "$root/usr/lib/udev/rules.d" \
    "$root/usr/libexec/tb321fu-haptics"
  printf '%s\n' \
    'Package: tb321fu-haptics' \
    'Version: 1' \
    'Architecture: arm64' \
    'Maintainer: fixture <fixture@example.invalid>' \
    'Depends: kmod, systemd, udev' \
    'Description: fixture' \
    > "$root/DEBIAN/control"
  haptics_write_maintainer_scripts "$root" "$kernel_release"
  printf 'keyboard\n' > "$root/etc/skel/.config/plasmakeyboardrc"
  printf '#!/bin/sh\nexit 0\n' > "$root/usr/bin/tb321fu-haptic-test"
  printf 'click firmware\n' > "$root/usr/lib/firmware/haptic_click.bin"
  printf 'ram firmware\n' > "$root/usr/lib/firmware/haptic_ram.bin"
  printf 'module bytes\n' > "$root/usr/lib/modules/$kernel_release/extra/aw86937-haptics.ko"
  printf 'service\n' > "$root/usr/lib/systemd/system/tb321fu-haptics.service"
  printf 'rules\n' > "$root/usr/lib/udev/rules.d/90-tb321fu-haptics.rules"
  printf '#!/bin/sh\nexit 0\n' > "$root/usr/libexec/tb321fu-haptics/bind-aw86937"
  chmod 0644 "$root/DEBIAN/control"
  chmod 0755 "$root/DEBIAN/postinst" "$root/DEBIAN/prerm" "$root/DEBIAN/postrm"
  find "$root" -type d -exec chmod 0755 {} +
  find "$root" -type f ! -path '*/DEBIAN/postinst' ! -path '*/DEBIAN/prerm' ! -path '*/DEBIAN/postrm' \
    ! -path '*/usr/bin/tb321fu-haptic-test' \
    ! -path '*/usr/libexec/tb321fu-haptics/bind-aw86937' -exec chmod 0644 {} +
  chmod 0755 \
    "$root/usr/bin/tb321fu-haptic-test" \
    "$root/usr/libexec/tb321fu-haptics/bind-aw86937"
}

build_deb() {
  local root=$1 output=$2
  dpkg-deb --build --root-owner-group "$root" "$output" >/dev/null
}

pkg="$tmp/pkg"
create_package_tree "$pkg"
ram_sha=$(sha256sum "$pkg/usr/lib/firmware/haptic_ram.bin" | awk '{print $1}')
click_sha=$(sha256sum "$pkg/usr/lib/firmware/haptic_click.bin" | awk '{print $1}')
module_sha=$(sha256sum "$pkg/usr/lib/modules/$kernel_release/extra/aw86937-haptics.ko" | awk '{print $1}')
helper_sha=$(sha256sum "$pkg/usr/bin/tb321fu-haptic-test" | awk '{print $1}')
good_deb="$tmp/good.deb"
build_deb "$pkg" "$good_deb"
bash "$verifier" "$pkg" "$good_deb" "$kernel_release" \
  "$ram_sha" "$click_sha" "$module_sha" "$helper_sha" >/dev/null

extra_payload="$tmp/extra-payload"
cp -a "$pkg" "$extra_payload"
printf '#!/bin/sh\nexit 0\n' > "$extra_payload/usr/libexec/tb321fu-haptics/unexpected-root-helper"
chmod 0755 "$extra_payload/usr/libexec/tb321fu-haptics/unexpected-root-helper"
build_deb "$extra_payload" "$tmp/extra-payload.deb"
require_failure 'unexpected file count' \
  bash "$verifier" "$extra_payload" "$tmp/extra-payload.deb" "$kernel_release" \
  "$ram_sha" "$click_sha" "$module_sha" "$helper_sha"

extra_control="$tmp/extra-control"
cp -a "$pkg" "$extra_control"
printf '#!/bin/sh\nexit 0\n' > "$extra_control/DEBIAN/preinst"
chmod 0755 "$extra_control/DEBIAN/preinst"
build_deb "$extra_control" "$tmp/extra-control.deb"
require_failure 'unexpected file count' \
  bash "$verifier" "$extra_control" "$tmp/extra-control.deb" "$kernel_release" \
  "$ram_sha" "$click_sha" "$module_sha" "$helper_sha"

wrong_path="$tmp/wrong-path"
cp -a "$pkg" "$wrong_path"
mv "$wrong_path/usr/lib/udev/rules.d/90-tb321fu-haptics.rules" \
  "$wrong_path/usr/lib/udev/rules.d/91-tb321fu-haptics.rules"
build_deb "$wrong_path" "$tmp/wrong-path.deb"
require_failure 'data path mismatch' \
  bash "$verifier" "$wrong_path" "$tmp/wrong-path.deb" "$kernel_release" \
  "$ram_sha" "$click_sha" "$module_sha" "$helper_sha"

wrong_mode="$tmp/wrong-mode"
cp -a "$pkg" "$wrong_mode"
chmod 0755 "$wrong_mode/usr/lib/systemd/system/tb321fu-haptics.service"
build_deb "$wrong_mode" "$tmp/wrong-mode.deb"
require_failure 'payload mode mismatch' \
  bash "$verifier" "$wrong_mode" "$tmp/wrong-mode.deb" "$kernel_release" \
  "$ram_sha" "$click_sha" "$module_sha" "$helper_sha"

wrong_bytes="$tmp/wrong-bytes"
cp -a "$pkg" "$wrong_bytes"
printf 'mutated ram firmware\n' > "$wrong_bytes/usr/lib/firmware/haptic_ram.bin"
build_deb "$wrong_bytes" "$tmp/wrong-bytes.deb"
require_failure 'changed payload bytes' \
  bash "$verifier" "$pkg" "$tmp/wrong-bytes.deb" "$kernel_release" \
  "$ram_sha" "$click_sha" "$module_sha" "$helper_sha"

missing_runtime_dep="$tmp/missing-runtime-dep"
cp -a "$pkg" "$missing_runtime_dep"
sed -i 's/^Depends: .*/Depends: kmod, udev/' "$missing_runtime_dep/DEBIAN/control"
build_deb "$missing_runtime_dep" "$tmp/missing-runtime-dep.deb"
require_failure 'lacks required runtime dependency: systemd' \
  bash "$verifier" "$missing_runtime_dep" "$tmp/missing-runtime-dep.deb" "$kernel_release" \
  "$ram_sha" "$click_sha" "$module_sha" "$helper_sha"

guessed_kernel_dep="$tmp/guessed-kernel-dep"
cp -a "$pkg" "$guessed_kernel_dep"
sed -i 's/^Depends: .*/Depends: kmod, systemd, udev, linux-image-test-kernel/' \
  "$guessed_kernel_dep/DEBIAN/control"
build_deb "$guessed_kernel_dep" "$tmp/guessed-kernel-dep.deb"
require_failure 'must not guess a distro kernel package ABI dependency' \
  bash "$verifier" "$guessed_kernel_dep" "$tmp/guessed-kernel-dep.deb" "$kernel_release" \
  "$ram_sha" "$click_sha" "$module_sha" "$helper_sha"

printf 'HAPTICS_DEB_FIXTURES=PASS\n'
