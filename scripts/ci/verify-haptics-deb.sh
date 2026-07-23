#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
. "$SCRIPT_DIR/common.sh"
. "$SCRIPT_DIR/haptics-maintainer-scripts.sh"

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
[[ $kernel_release =~ ^[0-9A-Za-z][0-9A-Za-z._+~-]{0,127}$ ]] ||
  ci_die "unsafe kernel release"
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
ci_require_cmd dash

verify_work=$(mktemp -d "${TMPDIR:-/tmp}/tb321fu-haptics-deb-verify.XXXXXX")
cleanup() { rm -rf -- "$verify_work"; }
trap cleanup EXIT

data_tar="$verify_work/data.tar"
data_root="$verify_work/data"
control_tar="$verify_work/control.tar"
control_root="$verify_work/control"
expected_data=(
  etc/modprobe.d/tb321fu-haptics.conf
  etc/skel/.config/plasmakeyboardrc
  usr/bin/tb321fu-haptic-test
  usr/lib/firmware/haptic_click.bin
  usr/lib/firmware/haptic_ram.bin
  "usr/lib/modules/$kernel_release/extra/aw86937-haptics.ko"
  usr/lib/systemd/system/tb321fu-haptics.service
  usr/lib/udev/rules.d/90-tb321fu-haptics.rules
  usr/libexec/tb321fu-haptics/bind-aw86937
)
expected_control=(control postinst postrm prerm)

verify_maintainer_script_contract() {
  local postinst=$1 prerm=$2 postrm=$3 depends required script

  for script in "$postinst" "$prerm" "$postrm"; do
    grep -Fx "KERNEL_RELEASE=$kernel_release" "$script" >/dev/null ||
      ci_die "haptics maintainer script does not embed the verified kernel release"
    if grep -Eq '(^|[^[:alnum:]_])uname([^[:alnum:]_]|$)' "$script"; then
      ci_die "haptics maintainer script must not derive a kernel release at runtime"
    fi
    if grep -Fq '|| true' "$script"; then
      ci_die "haptics maintainer script silently ignores a lifecycle failure"
    fi
  done
  grep -F 'modinfo -F vermagic "$module_path"' "$postinst" >/dev/null ||
    ci_die "haptics postinst lacks a target-module vermagic check"
  for script in "$postinst" "$postrm"; do
    grep -F 'depmod -a "$KERNEL_RELEASE"' "$script" >/dev/null ||
      ci_die "haptics maintainer script does not depmod the verified kernel release"
  done
  grep -F 'run_systemctl enable tb321fu-haptics.service' "$postinst" >/dev/null ||
    ci_die "haptics postinst does not require service enablement"
  grep -F 'run_systemctl is-enabled --quiet tb321fu-haptics.service' "$postinst" >/dev/null ||
    ci_die "haptics postinst does not verify service enablement"
  grep -F 'rollback_new_managed_want' "$postinst" >/dev/null ||
    ci_die "haptics postinst does not roll back newly created enablement"
  grep -F 'record_managed_want_state' "$postinst" >/dev/null ||
    ci_die "haptics postinst does not preserve pre-existing enablement"
  grep -F 'record_owned_managed_want' "$postinst" >/dev/null ||
    ci_die "haptics postinst does not record package-owned enablement"
  grep -F '/var/lib/tb321fu-haptics/managed-want' "$postinst" >/dev/null ||
    ci_die "haptics postinst lacks durable systemd-want ownership state"
  grep -F 'preserving modified systemd want' "$postrm" >/dev/null ||
    ci_die "haptics postrm can remove a user-modified systemd want"
  grep -F "legacy Y700 haptics payload remains" "$postinst" >/dev/null ||
    ci_die "haptics postinst does not reject unmigrated legacy payload"
  grep -F 'remove|deconfigure)' "$prerm" >/dev/null ||
    ci_die "haptics prerm does not scope pre-removal lifecycle actions"
  grep -F 'run_systemctl stop tb321fu-haptics.service' "$prerm" >/dev/null ||
    ci_die "haptics prerm does not stop the service before removal"
  grep -F 'remove_managed_want tb321fu-haptics.service' "$postrm" >/dev/null ||
    ci_die "haptics postrm does not remove service enablement"
  grep -F 'remove|purge)' "$postrm" >/dev/null ||
    ci_die "haptics postrm does not scope removal lifecycle actions"

  depends=$(dpkg-deb -f "$package_deb" Depends)
  for required in kmod systemd udev; do
    case ", $depends," in
      *", $required,"*|*", $required ("*|*", $required |"*) ;;
      *) ci_die "haptics package lacks required runtime dependency: $required" ;;
    esac
  done
  case "$depends" in
    *linux-image-*|*linux-modules-*)
      ci_die "haptics package must not guess a distro kernel package ABI dependency"
      ;;
  esac
}

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
grep -Fxq 'blacklist aw86937_y700' "$data_root/etc/modprobe.d/tb321fu-haptics.conf" ||
  ci_die "final haptics DEB does not blacklist the legacy AW86937 module"

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
  case "$relative" in postinst|postrm|prerm) expected_mode=755 ;; esac
  [ "$(stat -c '%a' "$control_root/$relative")" = "$expected_mode" ] ||
    ci_die "final haptics DEB control mode mismatch: $relative"
done

for relative in postinst prerm postrm; do
  rendered="$verify_work/rendered-$relative"
  haptics_render_maintainer_template \
    "$SCRIPT_DIR/haptics-control-templates/$relative.in" "$rendered" "$kernel_release" ||
    ci_die "cannot render haptics $relative template"
  cmp -s "$rendered" "$control_root/$relative" ||
    ci_die "final haptics DEB $relative differs from the producer template"
done
verify_maintainer_script_contract \
  "$control_root/postinst" "$control_root/prerm" "$control_root/postrm"

printf 'HAPTICS_DEB_CONTRACT=PASS\n'
