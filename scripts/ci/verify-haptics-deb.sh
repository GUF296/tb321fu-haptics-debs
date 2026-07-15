#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
. "$SCRIPT_DIR/common.sh"

[ "$#" -eq 7 ] || ci_die \
  "usage: verify-haptics-deb.sh PACKAGE_TREE DEB KERNEL_RELEASE RAM_SHA256 CLICK_SHA256 MODULE_SHA256 HELPER_SHA256"

pkg=$(realpath -e -- "$1")
package_deb=$(realpath -e -- "$2")
kernel_release=$3
haptics_ram_firmware_sha256=$4
haptics_click_firmware_sha256=$5
haptics_module_sha256=$6
haptics_test_helper_binary_sha256=$7

[ -d "$pkg" ] || ci_die "package tree is not a directory"
[ -f "$package_deb" ] && [ ! -L "$package_deb" ] || ci_die "DEB is not a regular file"
case "$kernel_release" in
  ''|*/*|*\\*|.*|*..*) ci_die "unsafe kernel release" ;;
esac
for digest in \
  "$haptics_ram_firmware_sha256" \
  "$haptics_click_firmware_sha256" \
  "$haptics_module_sha256" \
  "$haptics_test_helper_binary_sha256"; do
  [[ $digest =~ ^[0-9a-f]{64}$ ]] || ci_die "expected digest must be lowercase SHA-256"
done

ci_require_cmd cmp
ci_require_cmd dpkg-deb
ci_require_cmd sha256sum

verify_work=$(mktemp -d "${TMPDIR:-/tmp}/tb321fu-haptics-deb-verify.XXXXXX")
cleanup() { rm -rf -- "$verify_work"; }
trap cleanup EXIT

data_tar="$verify_work/data.tar"
data_root="$verify_work/data"
control_tar="$verify_work/control.tar"
control_root="$verify_work/control"
expected_data=(
  etc/skel/.config/plasmakeyboardrc
  usr/bin/tb321fu-haptic-test
  usr/lib/firmware/haptic_click.bin
  usr/lib/firmware/haptic_ram.bin
  "usr/lib/modules/$kernel_release/extra/aw86937-haptics.ko"
  usr/lib/systemd/system/tb321fu-haptics.service
  usr/lib/udev/rules.d/90-tb321fu-haptics.rules
  usr/libexec/tb321fu-haptics/bind-aw86937
)
expected_control=(control postinst postrm)

dpkg-deb --fsys-tarfile "$package_deb" > "$data_tar"
(umask 022; ci_extract_archive "$data_tar" "$data_root")
bad_member=$(find "$data_root" ! -type d ! -type f -print -quit)
[ -z "$bad_member" ] ||
  ci_die "final haptics DEB data contains a non-regular member: ${bad_member#"$data_root"/}"
bad_directory=$(find "$data_root" -mindepth 1 -type d ! -perm 0755 -print -quit)
[ -z "$bad_directory" ] ||
  ci_die "final haptics DEB data contains a non-0755 directory: ${bad_directory#"$data_root"/}"
mapfile -t actual_data < <(find "$data_root" -type f -printf '%P\n' | sort)
[ "${#actual_data[@]}" -eq "${#expected_data[@]}" ] ||
  ci_die "final haptics DEB data has an unexpected file count"
for index in "${!expected_data[@]}"; do
  relative=${expected_data[$index]}
  [ "${actual_data[$index]}" = "$relative" ] ||
    ci_die "final haptics DEB data path mismatch: expected $relative, got ${actual_data[$index]}"
  cmp -s "$pkg/$relative" "$data_root/$relative" ||
    ci_die "final haptics DEB changed payload bytes: $relative"
  case "$relative" in
    usr/bin/tb321fu-haptic-test|usr/libexec/tb321fu-haptics/bind-aw86937)
      expected_mode=755
      ;;
    *) expected_mode=644 ;;
  esac
  [ "$(stat -c '%a' "$data_root/$relative")" = "$expected_mode" ] ||
    ci_die "final haptics DEB payload mode mismatch: $relative"
done
[ "$(sha256sum "$data_root/usr/lib/firmware/haptic_ram.bin" | awk '{print $1}')" = "$haptics_ram_firmware_sha256" ] ||
  ci_die "final haptics DEB haptic_ram.bin digest mismatch"
[ "$(sha256sum "$data_root/usr/lib/firmware/haptic_click.bin" | awk '{print $1}')" = "$haptics_click_firmware_sha256" ] ||
  ci_die "final haptics DEB haptic_click.bin digest mismatch"
[ "$(sha256sum "$data_root/usr/lib/modules/$kernel_release/extra/aw86937-haptics.ko" | awk '{print $1}')" = "$haptics_module_sha256" ] ||
  ci_die "final haptics DEB module digest mismatch"
[ "$(sha256sum "$data_root/usr/bin/tb321fu-haptic-test" | awk '{print $1}')" = "$haptics_test_helper_binary_sha256" ] ||
  ci_die "final haptics DEB helper digest mismatch"

dpkg-deb --ctrl-tarfile "$package_deb" > "$control_tar"
(umask 022; ci_extract_archive "$control_tar" "$control_root")
bad_member=$(find "$control_root" ! -type d ! -type f -print -quit)
[ -z "$bad_member" ] ||
  ci_die "final haptics DEB control contains a non-regular member: ${bad_member#"$control_root"/}"
bad_directory=$(find "$control_root" -mindepth 1 -type d ! -perm 0755 -print -quit)
[ -z "$bad_directory" ] ||
  ci_die "final haptics DEB control contains a non-0755 directory: ${bad_directory#"$control_root"/}"
mapfile -t actual_control < <(find "$control_root" -type f -printf '%P\n' | sort)
[ "${#actual_control[@]}" -eq "${#expected_control[@]}" ] ||
  ci_die "final haptics DEB control has an unexpected file count"
for index in "${!expected_control[@]}"; do
  relative=${expected_control[$index]}
  [ "${actual_control[$index]}" = "$relative" ] ||
    ci_die "final haptics DEB control path mismatch: expected $relative, got ${actual_control[$index]}"
  cmp -s "$pkg/DEBIAN/$relative" "$control_root/$relative" ||
    ci_die "final haptics DEB changed control bytes: $relative"
  expected_mode=644
  case "$relative" in postinst|postrm) expected_mode=755 ;; esac
  [ "$(stat -c '%a' "$control_root/$relative")" = "$expected_mode" ] ||
    ci_die "final haptics DEB control mode mismatch: $relative"
done

printf 'HAPTICS_DEB_CONTRACT=PASS\n'
