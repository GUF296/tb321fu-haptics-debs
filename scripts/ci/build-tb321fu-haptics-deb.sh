#!/usr/bin/env bash
set -euo pipefail
umask 022
export LC_ALL=C

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
. "$SCRIPT_DIR/common.sh"

usage() {
  cat <<USAGE
Usage: $(basename "$0")

Build source-based TB321FU AW86937 haptics Debian package.

Environment inputs:
  OUTPUT_DIR                 default: out/tb321fu-haptics-debs
  ARCH                       default: arm64
  HAPTICS_DEB_VERSION        default: 20260627.1
  HAPTICS_SOURCE_ARCHIVE     source freeze archive containing haptics/daily-current
  HAPTICS_SOURCE_ARCHIVE_SHA256
  HAPTICS_SOURCE_DIR         source freeze directory containing haptics/daily-current
  HAPTICS_GIT_DIR            optional external Git object database
  EXPECTED_HAPTICS_PRODUCER_COMMIT
                              required exact 40-hex haptics producer commit
  KERNEL_SOURCE_ARCHIVE      kernel source archive
  KERNEL_SOURCE_ARCHIVE_SHA256
  KERNEL_SOURCE_DIR          kernel source directory
  KERNEL_BUILD_ARCHIVE       kernel build output archive containing generated headers
  KERNEL_BUILD_ARCHIVE_SHA256
  KERNEL_BUILD_DIR           kernel build output directory
  KERNEL_GIT_DIR             optional external Git object database
  KERNEL_BUNDLE_METADATA     optional KERNEL-BUNDLE.tsv path or HTTPS URL
  KERNEL_BUNDLE_METADATA_SHA256
  EXPECTED_KERNEL_SOURCE_COMMIT
                              optional exact 40-hex source identity
  SOURCE_DATE_EPOCH          reproducible build timestamp
  HAPTICS_STRIP              strip binaries/modules after build, default: 0
USAGE
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  exit 0
fi

ci_require_cmd make
ci_require_cmd python3
ci_require_cmd rsync
ci_require_cmd dpkg-deb
ci_require_cmd sha256sum
ci_require_cmd aarch64-linux-gnu-gcc
ci_require_cmd aarch64-linux-gnu-strip
ci_require_cmd modinfo
ci_require_cmd dpkg
ci_require_cmd cmp

OUTPUT_DIR=${OUTPUT_DIR:-out/tb321fu-haptics-debs}
ARCH=${ARCH:-arm64}
HAPTICS_DEB_VERSION=${HAPTICS_DEB_VERSION:-20260627.1}
HAPTICS_SOURCE_ARCHIVE=${HAPTICS_SOURCE_ARCHIVE:-}
HAPTICS_SOURCE_ARCHIVE_SHA256=${HAPTICS_SOURCE_ARCHIVE_SHA256:-}
HAPTICS_SOURCE_DIR=${HAPTICS_SOURCE_DIR:-}
HAPTICS_GIT_DIR=${HAPTICS_GIT_DIR:-}
EXPECTED_HAPTICS_PRODUCER_COMMIT=${EXPECTED_HAPTICS_PRODUCER_COMMIT:-}
KERNEL_SOURCE_ARCHIVE=${KERNEL_SOURCE_ARCHIVE:-}
KERNEL_SOURCE_ARCHIVE_SHA256=${KERNEL_SOURCE_ARCHIVE_SHA256:-}
KERNEL_SOURCE_DIR=${KERNEL_SOURCE_DIR:-}
KERNEL_BUILD_ARCHIVE=${KERNEL_BUILD_ARCHIVE:-}
KERNEL_BUILD_ARCHIVE_SHA256=${KERNEL_BUILD_ARCHIVE_SHA256:-}
KERNEL_BUILD_DIR=${KERNEL_BUILD_DIR:-}
KERNEL_GIT_DIR=${KERNEL_GIT_DIR:-}
KERNEL_BUNDLE_METADATA=${KERNEL_BUNDLE_METADATA:-}
KERNEL_BUNDLE_METADATA_SHA256=${KERNEL_BUNDLE_METADATA_SHA256:-}
EXPECTED_KERNEL_SOURCE_COMMIT=${EXPECTED_KERNEL_SOURCE_COMMIT:-}
HAPTICS_STRIP=${HAPTICS_STRIP:-0}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
kernel_build_archive_identity=local-build-directory
kernel_bundle_id=unbound
kernel_bundle_config_sha256=unbound

[ "$ARCH" = arm64 ] || ci_die "unsupported ARCH=$ARCH; only arm64 is supported"
[[ $HAPTICS_DEB_VERSION =~ ^[0-9][0-9A-Za-z.+~_-]{0,63}$ ]] || ci_die "unsafe HAPTICS_DEB_VERSION"
dpkg --validate-version "$HAPTICS_DEB_VERSION" >/dev/null || ci_die "invalid HAPTICS_DEB_VERSION"
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]{1,10}$ ]] || ci_die "invalid SOURCE_DATE_EPOCH"
[[ $EXPECTED_HAPTICS_PRODUCER_COMMIT =~ ^[0-9a-f]{40}$ ]] ||
  ci_die "EXPECTED_HAPTICS_PRODUCER_COMMIT must be 40 lowercase hex characters"
if [ -n "$EXPECTED_KERNEL_SOURCE_COMMIT" ]; then
  [[ $EXPECTED_KERNEL_SOURCE_COMMIT =~ ^[0-9a-f]{40}$ ]] || ci_die "invalid EXPECTED_KERNEL_SOURCE_COMMIT"
  ci_require_cmd git
fi
export SOURCE_DATE_EPOCH
haptics_producer_commit=
haptics_producer_state=
haptics_driver_source_sha256=
haptics_build_source_sha256=
haptics_ram_firmware_sha256=
haptics_click_firmware_sha256=
haptics_test_helper_sha256=
haptics_module_sha256=
haptics_test_helper_binary_sha256=
haptics_snapshot_work=
haptics_snapshot_driver=
haptics_snapshot_ram_firmware=
haptics_snapshot_click_firmware=
haptics_snapshot_helper=
haptics_build_source_path=
haptics_deb_name=
producer_bundle=
output_path=
output_stage=

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/tb321fu-haptics-build.XXXXXX")

cleanup() {
  chmod -R u+w "$work_dir" 2>/dev/null || true
  rm -rf "$work_dir"
  if [ -n "$output_stage" ] && [ -d "$output_stage" ]; then
    chmod -R u+w "$output_stage" 2>/dev/null || true
    rm -rf -- "$output_stage"
  fi
}
trap cleanup EXIT

output_requested=$(ci_abs_path "$OUTPUT_DIR")
output_parent=$(dirname -- "$output_requested")
output_name=$(basename -- "$output_requested")
[[ $output_name =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] ||
  ci_die "unsafe OUTPUT_DIR basename: $output_name"
mkdir -p "$output_parent"
output_parent=$(realpath -e -- "$output_parent")
output_path="$output_parent/$output_name"
[ ! -e "$output_path" ] || ci_die "refusing stale OUTPUT_DIR: $output_path"
output_stage=$(mktemp -d "$output_parent/.${output_name}.staging.XXXXXX")
chmod 0700 "$output_stage"
OUTPUT_DIR=$output_stage

find_haptics_source_root() {
  local root=$1 found

  if [ -f "$root/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c" ] && \
     [ -f "$root/haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin" ] && \
     [ -f "$root/haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin" ]; then
    printf '%s\n' "$root"
    return 0
  fi

  found=$(find "$root" -type f -path '*/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c' -print -quit)
  [ -n "$found" ] || return 1
  found=${found%/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c}
  [ -f "$found/haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin" ] || return 1
  [ -f "$found/haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin" ] || return 1
  printf '%s\n' "$found"
}

find_kernel_source_root() {
  local root=$1 found

  if [ -f "$root/Makefile" ] && [ -d "$root/scripts" ] && [ -d "$root/drivers" ]; then
    printf '%s\n' "$root"
    return 0
  fi

  found=$(find "$root" -type f -path '*/scripts/Makefile.build' -print -quit)
  [ -n "$found" ] || return 1
  found=${found%/scripts/Makefile.build}
  [ -f "$found/Makefile" ] || return 1
  [ -d "$found/drivers" ] || return 1
  printf '%s\n' "$found"
}

find_kernel_build_root() {
  local root=$1 found

  if [ -f "$root/.config" ] && \
     [ -f "$root/Module.symvers" ] && \
     [ -f "$root/include/generated/autoconf.h" ] && \
     [ -f "$root/include/config/kernel.release" ]; then
    printf '%s\n' "$root"
    return 0
  fi

  found=$(find "$root" -type f -path '*/include/config/kernel.release' -print -quit)
  [ -n "$found" ] || return 1
  found=${found%/include/config/kernel.release}
  [ -f "$found/.config" ] || return 1
  [ -f "$found/Module.symvers" ] || return 1
  [ -f "$found/include/generated/autoconf.h" ] || return 1
  printf '%s\n' "$found"
}

load_kernel_bundle_metadata() {
  local metadata="$work_dir/KERNEL-BUNDLE.tsv"
  local canonical="$work_dir/KERNEL-BUNDLE.canonical.tsv"
  local -a lines verify_args

  [ -n "$KERNEL_BUNDLE_METADATA" ] || return 0
  ci_download "$KERNEL_BUNDLE_METADATA" "$metadata" "$KERNEL_BUNDLE_METADATA_SHA256"
  verify_args=("$metadata" --emit-tsv)
  if [ -n "$EXPECTED_KERNEL_SOURCE_COMMIT" ]; then
    verify_args+=(--expect "kernel-source-commit=$EXPECTED_KERNEL_SOURCE_COMMIT")
  fi
  python3 "$SCRIPT_DIR/verify-kernel-bundle.py" "${verify_args[@]}" > "$canonical" ||
    ci_die "invalid KERNEL-BUNDLE.tsv"

  mapfile -t lines < "$canonical"
  kernel_bundle_commit=${lines[1]#*$'\t'}
  kernel_bundle_release=${lines[2]#*$'\t'}
  kernel_bundle_config_sha256=${lines[3]#*$'\t'}
  kernel_bundle_epoch=${lines[4]#*$'\t'}
  kernel_bundle_id=${lines[9]#*$'\t'}

  if [ -n "$EXPECTED_KERNEL_SOURCE_COMMIT" ]; then
    : # The shared verifier enforced the exact expected commit.
  else
    EXPECTED_KERNEL_SOURCE_COMMIT=$kernel_bundle_commit
  fi
  SOURCE_DATE_EPOCH=$kernel_bundle_epoch
  export SOURCE_DATE_EPOCH
}

prepare_inputs() {
  local archive extract

  if [ -n "$HAPTICS_SOURCE_DIR" ]; then
    haptics_root=$(find_haptics_source_root "$HAPTICS_SOURCE_DIR") || ci_die "HAPTICS_SOURCE_DIR does not contain haptics source freeze"
  else
    [ -n "$HAPTICS_SOURCE_ARCHIVE" ] || ci_die "set HAPTICS_SOURCE_ARCHIVE or HAPTICS_SOURCE_DIR"
    archive="$work_dir/haptics-source.archive"
    extract="$work_dir/haptics-source"
    ci_download "$HAPTICS_SOURCE_ARCHIVE" "$archive" "$HAPTICS_SOURCE_ARCHIVE_SHA256"
    ci_extract_archive "$archive" "$extract"
    haptics_root=$(find_haptics_source_root "$extract") || ci_die "HAPTICS_SOURCE_ARCHIVE does not contain haptics source freeze"
  fi

  if [ -n "$KERNEL_SOURCE_DIR" ]; then
    kernel_source_root=$(find_kernel_source_root "$KERNEL_SOURCE_DIR") || ci_die "KERNEL_SOURCE_DIR does not contain kernel source"
  else
    [ -n "$KERNEL_SOURCE_ARCHIVE" ] || ci_die "set KERNEL_SOURCE_ARCHIVE or KERNEL_SOURCE_DIR"
    archive="$work_dir/kernel-source.archive"
    extract="$work_dir/kernel-source"
    ci_download "$KERNEL_SOURCE_ARCHIVE" "$archive" "$KERNEL_SOURCE_ARCHIVE_SHA256"
    ci_extract_archive "$archive" "$extract"
    kernel_source_root=$(find_kernel_source_root "$extract") || ci_die "KERNEL_SOURCE_ARCHIVE does not contain kernel source"
  fi

  if [ -n "$KERNEL_BUILD_DIR" ]; then
    kernel_build_root=$(find_kernel_build_root "$KERNEL_BUILD_DIR") || ci_die "KERNEL_BUILD_DIR does not contain kernel build output"
  else
    [ -n "$KERNEL_BUILD_ARCHIVE" ] || ci_die "set KERNEL_BUILD_ARCHIVE or KERNEL_BUILD_DIR"
    archive="$work_dir/kernel-build.archive"
    extract="$work_dir/kernel-build"
    ci_download "$KERNEL_BUILD_ARCHIVE" "$archive" "$KERNEL_BUILD_ARCHIVE_SHA256"
    kernel_build_archive_identity=$(sha256sum "$archive" | awk '{print $1}')
    ci_extract_archive "$archive" "$extract"
    kernel_build_root=$(find_kernel_build_root "$extract") || ci_die "KERNEL_BUILD_ARCHIVE does not contain kernel build output"
  fi

  load_kernel_bundle_metadata
  kernel_release=$(cat "$kernel_build_root/include/config/kernel.release")
  if [ "$kernel_bundle_id" != unbound ]; then
    [ "$kernel_release" = "$kernel_bundle_release" ] || ci_die "kernel release differs from KERNEL-BUNDLE.tsv"
    [ "$(sha256sum "$kernel_build_root/.config" | awk '{print $1}')" = "$kernel_bundle_config_sha256" ] ||
      ci_die "kernel build config differs from KERNEL-BUNDLE.tsv"
  fi
  if [ -n "$EXPECTED_KERNEL_SOURCE_COMMIT" ]; then
    verify_kernel_source_state "before package build"
    case "$kernel_release" in
      *-g"${EXPECTED_KERNEL_SOURCE_COMMIT:0:12}"*) ;;
      *) ci_die "kernel release does not bind expected source commit: $kernel_release" ;;
    esac
  fi
  ci_log "haptics source root: $haptics_root"
  ci_log "kernel source root: $kernel_source_root"
  ci_log "kernel build root: $kernel_build_root"
  ci_log "kernel release: $kernel_release"
}

verify_haptics_producer_state() {
  local phase=$1 actual

  actual=$(ci_verify_clean_git_commit \
    "$haptics_root" "$EXPECTED_HAPTICS_PRODUCER_COMMIT" "$HAPTICS_GIT_DIR")
  [ "$actual" = "$EXPECTED_HAPTICS_PRODUCER_COMMIT" ] ||
    ci_die "haptics producer changed $phase"
  haptics_producer_commit=$actual
  haptics_producer_state=clean
  ci_log "haptics producer state verified $phase: $actual"
}

verify_kernel_source_state() {
  local phase=$1 actual

  [ -n "$EXPECTED_KERNEL_SOURCE_COMMIT" ] || return 0
  actual=$(ci_verify_clean_git_commit \
    "$kernel_source_root" "$EXPECTED_KERNEL_SOURCE_COMMIT" "$KERNEL_GIT_DIR")
  [ "$actual" = "$EXPECTED_KERNEL_SOURCE_COMMIT" ] ||
    ci_die "kernel source changed $phase"
  ci_log "kernel source state verified $phase: $actual"
}

verify_kernel_build_state() {
  local phase=$1 actual_release actual_config_sha256

  actual_release=$(cat "$kernel_build_root/include/config/kernel.release")
  [ "$actual_release" = "$kernel_release" ] ||
    ci_die "kernel build release changed $phase: expected $kernel_release, got $actual_release"
  if [ "$kernel_bundle_id" != unbound ]; then
    [ "$actual_release" = "$kernel_bundle_release" ] ||
      ci_die "kernel build release differs from KERNEL-BUNDLE.tsv $phase"
    actual_config_sha256=$(sha256sum "$kernel_build_root/.config" | awk '{print $1}')
    [ "$actual_config_sha256" = "$kernel_bundle_config_sha256" ] ||
      ci_die "kernel build config differs from KERNEL-BUNDLE.tsv $phase: expected $kernel_bundle_config_sha256, got $actual_config_sha256"
  fi
  ci_log "kernel build state verified $phase: $actual_release"
}

prepare_haptics_source_snapshot() {
  local source_root

  haptics_snapshot_work="$work_dir/haptics-source-snapshot"
  source_root="$haptics_snapshot_work/source"
  haptics_snapshot_driver="$source_root/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c"
  haptics_snapshot_ram_firmware="$source_root/haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin"
  haptics_snapshot_click_firmware="$source_root/haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin"
  haptics_snapshot_helper="$source_root/haptics/baseline-20260614-daily-clean/testing-tools/y700-haptic-test.c"

  ci_export_git_file "$haptics_root" "$EXPECTED_HAPTICS_PRODUCER_COMMIT" \
    haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c \
    "$haptics_snapshot_driver" "$HAPTICS_GIT_DIR"
  ci_export_git_file "$haptics_root" "$EXPECTED_HAPTICS_PRODUCER_COMMIT" \
    haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin \
    "$haptics_snapshot_ram_firmware" "$HAPTICS_GIT_DIR"
  ci_export_git_file "$haptics_root" "$EXPECTED_HAPTICS_PRODUCER_COMMIT" \
    haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin \
    "$haptics_snapshot_click_firmware" "$HAPTICS_GIT_DIR"
  ci_export_git_file "$haptics_root" "$EXPECTED_HAPTICS_PRODUCER_COMMIT" \
    haptics/baseline-20260614-daily-clean/testing-tools/y700-haptic-test.c \
    "$haptics_snapshot_helper" "$HAPTICS_GIT_DIR"
  haptics_driver_source_sha256=$(sha256sum "$haptics_snapshot_driver" | awk '{print $1}')
  haptics_ram_firmware_sha256=$(sha256sum "$haptics_snapshot_ram_firmware" | awk '{print $1}')
  haptics_click_firmware_sha256=$(sha256sum "$haptics_snapshot_click_firmware" | awk '{print $1}')
  haptics_test_helper_sha256=$(sha256sum "$haptics_snapshot_helper" | awk '{print $1}')
  [ "$haptics_driver_source_sha256" = 2e0cb7b739496ff6cf4011244ec9c0b2a2367896de65784041018b9d62186e48 ] ||
    ci_die "AW86937 driver source does not match the canonical corrected source: $haptics_driver_source_sha256"
  find "$haptics_snapshot_work" -type f -exec chmod 0444 {} +
  find "$haptics_snapshot_work" -type d -exec chmod 0555 {} +
}

verify_private_haptics_source_snapshot() {
  local label=$1

  [ -f "$haptics_snapshot_driver" ] && [ ! -L "$haptics_snapshot_driver" ] ||
    ci_die "private AW86937 driver snapshot is not regular $label"
  [ -f "$haptics_snapshot_ram_firmware" ] && [ ! -L "$haptics_snapshot_ram_firmware" ] ||
    ci_die "private haptic_ram.bin snapshot is not regular $label"
  [ -f "$haptics_snapshot_click_firmware" ] && [ ! -L "$haptics_snapshot_click_firmware" ] ||
    ci_die "private haptic_click.bin snapshot is not regular $label"
  [ -f "$haptics_snapshot_helper" ] && [ ! -L "$haptics_snapshot_helper" ] ||
    ci_die "private haptics helper snapshot is not regular $label"
  [ "$(sha256sum "$haptics_snapshot_driver" | awk '{print $1}')" = "$haptics_driver_source_sha256" ] ||
    ci_die "private AW86937 driver snapshot changed $label"
  [ "$(sha256sum "$haptics_snapshot_ram_firmware" | awk '{print $1}')" = "$haptics_ram_firmware_sha256" ] ||
    ci_die "private haptic_ram.bin snapshot changed $label"
  [ "$(sha256sum "$haptics_snapshot_click_firmware" | awk '{print $1}')" = "$haptics_click_firmware_sha256" ] ||
    ci_die "private haptic_click.bin snapshot changed $label"
  [ "$(sha256sum "$haptics_snapshot_helper" | awk '{print $1}')" = "$haptics_test_helper_sha256" ] ||
    ci_die "private haptics helper snapshot changed $label"
}

create_haptics_producer_bundle() {
  local bundle_ref=refs/heads/tb321fu-haptics-producer

  producer_bundle="$work_dir/HAPTICS-PRODUCER.bundle"
  ci_create_exact_git_bundle \
    "$haptics_root" \
    "$EXPECTED_HAPTICS_PRODUCER_COMMIT" \
    "$producer_bundle" \
    "$bundle_ref" \
    "$HAPTICS_GIT_DIR"
}

kernel_make() {
  if [ -n "$KERNEL_GIT_DIR" ]; then
    ci_sanitized_git_env \
      env GIT_DIR="$KERNEL_GIT_DIR" GIT_WORK_TREE="$kernel_source_root" \
      make -C "$kernel_source_root" "$@"
  else
    ci_sanitized_git_env make -C "$kernel_source_root" "$@"
  fi
}

prepare_kernel_host_tools() {
  # Kernel build output archives can contain host tools from the machine that
  # prepared the SDK. Rebuild them on the current runner before external module
  # compilation so the SDK works on both x86_64 and arm64 hosts.
  rm -f \
    "$kernel_build_root/scripts/basic/fixdep" \
    "$kernel_build_root/scripts/mod/modpost"
  kernel_make O="$kernel_build_root" \
    ARCH=arm64 \
    CROSS_COMPILE=aarch64-linux-gnu- \
    scripts_basic scripts/mod/

  [ -x "$kernel_build_root/scripts/basic/fixdep" ] || ci_die "missing rebuilt kernel host tool: scripts/basic/fixdep"
  [ -x "$kernel_build_root/scripts/mod/modpost" ] || ci_die "missing rebuilt kernel host tool: scripts/mod/modpost"
  verify_kernel_build_state "after host-tool preparation"
}

patch_source_for_standard_module_name() {
  local src=$1

  sed -i \
    -e 's/Lenovo Y700 AW86937 input force-feedback haptics driver/Lenovo TB321FU AW86937 input force-feedback haptics driver/g' \
    -e 's/\.name = "aw86937-y700"/.name = "aw86937-haptics"/g' \
    "$src"

  if ! grep -q '"aw86937_haptics"' "$src"; then
    sed -i '/{ "aw86937_y700" }/i\	{ "aw86937_haptics" },' "$src"
  fi

  grep -q '\.name = "aw86937-haptics"' "$src" || ci_die "failed to patch i2c driver name"
  grep -q '"aw86937_haptics"' "$src" || ci_die "failed to add standard i2c id"
}

write_control() {
  local pkgdir=$1

  mkdir -p "$pkgdir/DEBIAN"
  cat > "$pkgdir/DEBIAN/control" <<EOF_CONTROL
Package: tb321fu-haptics
Version: $HAPTICS_DEB_VERSION
Section: misc
Priority: optional
Architecture: $ARCH
Maintainer: GUF296 <guf296@users.noreply.github.com>
Depends: kmod, systemd, udev, coreutils, findutils, feedbackd, feedbackd-device-themes
Conflicts: y700-haptics
Replaces: y700-haptics
Description: AW86937 haptics support for Lenovo Legion Y700 TB321FU
 Source-built AW86937 force-feedback haptics module, firmware, feedbackd udev
 integration and TB321FU boot-time binding glue.
EOF_CONTROL
}

write_maintainer_scripts() {
  local pkgdir=$1

  cat > "$pkgdir/DEBIAN/postinst" <<'EOF_POSTINST'
#!/bin/sh
set -e

if command -v depmod >/dev/null 2>&1; then
  depmod -a || true
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop y700-aw86937-haptics.service >/dev/null 2>&1 || true
  systemctl disable y700-aw86937-haptics.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/y700-aw86937-haptics.service
  rm -f /etc/udev/rules.d/90-y700-haptics.rules
  rm -f /usr/local/sbin/y700-aw86937-bind
  systemctl daemon-reload || true
  systemctl enable tb321fu-haptics.service >/dev/null 2>&1 || true
fi
if command -v udevadm >/dev/null 2>&1; then
  udevadm control --reload-rules || true
fi
exit 0
EOF_POSTINST

  cat > "$pkgdir/DEBIAN/postrm" <<'EOF_POSTRM'
#!/bin/sh
set -e

if command -v depmod >/dev/null 2>&1; then
  depmod -a || true
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi
if command -v udevadm >/dev/null 2>&1; then
  udevadm control --reload-rules || true
fi
exit 0
EOF_POSTRM

  chmod 0755 "$pkgdir/DEBIAN/postinst" "$pkgdir/DEBIAN/postrm"
}

write_bind_script() {
  local dest=$1

  cat > "$dest" <<'EOF_BIND'
#!/bin/sh
set -eu

find_haptic_adapter()
{
	for dev in /sys/bus/i2c/devices/i2c-*; do
		[ -e "$dev/name" ] || continue
		real=$(readlink -f "$dev" || true)
		case "$real" in
			*a9c000.i2c*) basename "$dev" | sed 's/^i2c-//'; return 0 ;;
		esac
	done
	return 1
}

load_driver()
{
	if lsmod | awk '{print $1}' | grep -Eq '^(aw86937_haptics|aw86937_y700)$'; then
		return 0
	fi
	modprobe aw86937_haptics 2>/dev/null && return 0
	modprobe aw86937_y700 2>/dev/null && return 0

	krel=$(uname -r)
	for module_path in \
		"/lib/modules/$krel/extra/aw86937-haptics.ko" \
		"/lib/modules/$krel/extra/aw86937-y700.ko" \
		"/usr/lib/modules/$krel/extra/aw86937-haptics.ko" \
		"/usr/lib/modules/$krel/extra/aw86937-y700.ko"; do
		[ -f "$module_path" ] || continue
		insmod "$module_path" && return 0
	done

	echo "no AW86937 haptics module could be loaded" >&2
	return 1
}

is_known_haptic_name()
{
	case "$1" in
		aw86937_haptics|aw86937_y700|aw86937|haptic_hv|haptic_hv_r|haptic_hv_l|tb321fu-aw86937|y700-aw86937)
			return 0
			;;
	esac
	return 1
}

find_driver_dir()
{
	for driver in aw86937-haptics aw86937-y700; do
		[ -d "/sys/bus/i2c/drivers/$driver" ] || continue
		printf '%s\n' "/sys/bus/i2c/drivers/$driver"
		return 0
	done
	return 1
}

bind_existing_client()
{
	dev="$1"
	name="$2"
	driver_dir="$3"
	busdev=$(basename "$dev")

	if ! is_known_haptic_name "$name"; then
		echo "$dev already exists as $name" >&2
		exit 1
	fi

	if [ -e "$dev/driver" ]; then
		driver=$(basename "$(readlink -f "$dev/driver")")
		case "$driver" in
			aw86937-haptics|aw86937-y700) return 0 ;;
		esac
		echo "$dev is already bound to unexpected driver $driver" >&2
		exit 1
	fi

	printf '%s\n' "$busdev" > "$driver_dir/bind" 2>/dev/null || true

	for _ in $(seq 1 20); do
		if [ -e "$dev/driver" ]; then
			driver=$(basename "$(readlink -f "$dev/driver")")
			case "$driver" in
				aw86937-haptics|aw86937-y700) return 0 ;;
			esac
		fi
		sleep 0.1
	done

	echo "$dev did not bind to AW86937 haptics driver" >&2
	exit 1
}

adapter=""
for _ in $(seq 1 80); do
	adapter=$(find_haptic_adapter 2>/dev/null || true)
	[ -n "$adapter" ] && break
	sleep 0.25
done

if [ -z "$adapter" ]; then
	echo "a9c000.i2c adapter not found" >&2
	exit 1
fi

load_driver
driver_dir=$(find_driver_dir) || { echo "AW86937 haptics i2c driver not registered" >&2; exit 1; }

for spec in "0x5a:right" "0x5b:left"; do
	addr=${spec%%:*}
	dev="/sys/bus/i2c/devices/${adapter}-00${addr#0x}"
	if [ -e "$dev/name" ]; then
		name=$(cat "$dev/name")
		bind_existing_client "$dev" "$name" "$driver_dir"
		continue
	fi
	printf 'aw86937_haptics %s\n' "$addr" > "/sys/bus/i2c/devices/i2c-$adapter/new_device" 2>/dev/null || \
		printf 'aw86937_y700 %s\n' "$addr" > "/sys/bus/i2c/devices/i2c-$adapter/new_device"
done
EOF_BIND
  chmod 0755 "$dest"
}

write_systemd_unit() {
  local dest=$1

  cat > "$dest" <<'EOF_SERVICE'
[Unit]
Description=Bind Lenovo TB321FU AW86937 haptics
DefaultDependencies=no
After=systemd-udevd.service local-fs.target
Wants=systemd-udevd.service
Conflicts=y700-aw86937-haptics.service

[Service]
Type=oneshot
ExecStart=/usr/libexec/tb321fu-haptics/bind-aw86937
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF_SERVICE
  chmod 0644 "$dest"
}

write_udev_rules() {
  local dest=$1

  cat > "$dest" <<'EOF_UDEV'
# TB321FU AW86937 haptics expose standard Linux input force-feedback devices.
ACTION=="remove", GOTO="tb321fu_haptics_end"
SUBSYSTEM=="input", KERNEL=="event*", ATTRS{name}=="aw86937-haptics-left", GROUP="input", MODE="0666", TAG+="uaccess", ENV{FEEDBACKD_TYPE}="vibra", SYMLINK+="input/tb321fu-haptics-left"
SUBSYSTEM=="input", KERNEL=="event*", ATTRS{name}=="aw86937-haptics-right", GROUP="input", MODE="0666", TAG+="uaccess", ENV{FEEDBACKD_TYPE}="vibra", SYMLINK+="input/tb321fu-haptics-right"
LABEL="tb321fu_haptics_end"
EOF_UDEV
  chmod 0644 "$dest"
}

write_plasma_keyboard_default() {
  local dest=$1

  cat > "$dest" <<'EOF_CONF'
[General]
enabledLocales=en_US
soundEnabled=true
vibrationEnabled=true
vibrationMs=20
EOF_CONF
  chmod 0644 "$dest"
}

strip_if_requested() {
  [ "$HAPTICS_STRIP" = 1 ] || return 0
  aarch64-linux-gnu-strip --strip-unneeded "$@"
}

build_haptics_package() {
  local src="$work_dir/module-src"
  local pkg="$work_dir/pkg/tb321fu-haptics"
  local module="$src/aw86937-haptics.ko"
  local helper_src="$haptics_snapshot_helper"
  local driver_src="$haptics_snapshot_driver"
  local ram_firmware="$haptics_snapshot_ram_firmware"
  local click_firmware="$haptics_snapshot_click_firmware"

  ci_log "building aw86937-haptics external module"
  [ -f "$driver_src" ] || ci_die "missing AW86937 driver source"
  [ -f "$ram_firmware" ] || ci_die "missing haptic_ram.bin source"
  [ -f "$click_firmware" ] || ci_die "missing haptic_click.bin source"
  [ -f "$helper_src" ] || ci_die "missing haptics test helper source"
  verify_private_haptics_source_snapshot "before package input consumption"
  mkdir -p "$src"
  install -m 0644 "$driver_src" "$src/aw86937-haptics.c"
  [ "$(sha256sum "$src/aw86937-haptics.c" | awk '{print $1}')" = "$haptics_driver_source_sha256" ] ||
    ci_die "copied AW86937 driver differs from the Git-object snapshot"
  grep -q 'wait_event_timeout(haptics->play_wait' "$src/aw86937-haptics.c" ||
    ci_die "AW86937 driver lacks cancellable playback"
  grep -q 'pm_sleep_ptr(&aw86937_y700_pm_ops)' "$src/aw86937-haptics.c" ||
    ci_die "AW86937 driver lacks PM callbacks"
  if grep -Eq 'msleep\((duration_ms|play_ms)\)' "$src/aw86937-haptics.c"; then
    ci_die "AW86937 driver contains an uninterruptible effect wait"
  fi
  patch_source_for_standard_module_name "$src/aw86937-haptics.c"
  haptics_build_source_path="$src/aw86937-haptics.c"
  haptics_build_source_sha256=$(sha256sum "$haptics_build_source_path" | awk '{print $1}')
  cat > "$src/Makefile" <<'EOF_MAKE'
obj-m := aw86937-haptics.o
EOF_MAKE

  kernel_make O="$kernel_build_root" ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- M="$src" modules
  verify_kernel_build_state "after external module build"
  [ -f "$module" ] || ci_die "missing built module: $module"
  [ "$(sha256sum "$haptics_build_source_path" | awk '{print $1}')" = "$haptics_build_source_sha256" ] ||
    ci_die "patched AW86937 build source changed during module compilation"
  modinfo "$module" | tee "$work_dir/aw86937-haptics.modinfo"
  grep -q '^name:[[:space:]]*aw86937_haptics$' "$work_dir/aw86937-haptics.modinfo" || ci_die "unexpected module name"
  grep -q '^alias:[[:space:]]*i2c:aw86937_haptics$' "$work_dir/aw86937-haptics.modinfo" || ci_die "missing standard i2c alias"
  grep -q "^vermagic:[[:space:]]*$kernel_release " "$work_dir/aw86937-haptics.modinfo" || ci_die "module vermagic does not match $kernel_release"

  install -d -m 0755 \
    "$pkg/usr/lib/modules/$kernel_release/extra" \
    "$pkg/usr/lib/firmware" \
    "$pkg/usr/libexec/tb321fu-haptics" \
    "$pkg/usr/lib/systemd/system" \
    "$pkg/usr/lib/udev/rules.d" \
    "$pkg/etc/skel/.config" \
    "$pkg/usr/bin"

  install -m 0644 "$module" "$pkg/usr/lib/modules/$kernel_release/extra/aw86937-haptics.ko"
  install -m 0644 "$ram_firmware" "$pkg/usr/lib/firmware/haptic_ram.bin"
  install -m 0644 "$click_firmware" "$pkg/usr/lib/firmware/haptic_click.bin"
  [ "$(sha256sum "$pkg/usr/lib/firmware/haptic_ram.bin" | awk '{print $1}')" = "$haptics_ram_firmware_sha256" ] ||
    ci_die "packaged haptic_ram.bin differs from the Git-object snapshot"
  [ "$(sha256sum "$pkg/usr/lib/firmware/haptic_click.bin" | awk '{print $1}')" = "$haptics_click_firmware_sha256" ] ||
    ci_die "packaged haptic_click.bin differs from the Git-object snapshot"
  write_bind_script "$pkg/usr/libexec/tb321fu-haptics/bind-aw86937"
  write_systemd_unit "$pkg/usr/lib/systemd/system/tb321fu-haptics.service"
  write_udev_rules "$pkg/usr/lib/udev/rules.d/90-tb321fu-haptics.rules"
  write_plasma_keyboard_default "$pkg/etc/skel/.config/plasmakeyboardrc"

  aarch64-linux-gnu-gcc -O2 -Wall -Wextra -o "$pkg/usr/bin/tb321fu-haptic-test" "$helper_src"
  verify_private_haptics_source_snapshot "after package input consumption"
  chmod 0755 "$pkg/usr/bin/tb321fu-haptic-test"
  strip_if_requested "$pkg/usr/bin/tb321fu-haptic-test"

  strip_if_requested "$pkg/usr/lib/modules/$kernel_release/extra/aw86937-haptics.ko"
  haptics_module_sha256=$(sha256sum \
    "$pkg/usr/lib/modules/$kernel_release/extra/aw86937-haptics.ko" | awk '{print $1}')
  haptics_test_helper_binary_sha256=$(sha256sum \
    "$pkg/usr/bin/tb321fu-haptic-test" | awk '{print $1}')
  write_control "$pkg"
  write_maintainer_scripts "$pkg"

  find "$pkg" -type d -exec chmod 0755 {} +
  find "$pkg" -xdev -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  haptics_deb_name="tb321fu-haptics_${HAPTICS_DEB_VERSION}_${ARCH}.deb"
  deb="$OUTPUT_DIR/$haptics_deb_name"
  dpkg-deb --build --root-owner-group "$pkg" "$deb" >/dev/null
  verify_built_haptics_deb "$pkg" "$deb"
  sha256sum "$deb"
}

verify_built_haptics_deb() {
  bash "$SCRIPT_DIR/verify-haptics-deb.sh" \
    "$1" "$2" "$kernel_release" \
    "$haptics_ram_firmware_sha256" \
    "$haptics_click_firmware_sha256" \
    "$haptics_module_sha256" \
    "$haptics_test_helper_binary_sha256" >/dev/null
}

stage_haptics_source_snapshot() {
  local stage="$OUTPUT_DIR/HAPTICS-SOURCE-SNAPSHOT"
  local source_root="$stage/source"

  rm -rf -- "$stage"
  install -D -m 0644 "$haptics_snapshot_driver" \
    "$source_root/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c"
  install -D -m 0644 "$haptics_snapshot_ram_firmware" \
    "$source_root/haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin"
  install -D -m 0644 "$haptics_snapshot_click_firmware" \
    "$source_root/haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin"
  install -D -m 0644 "$haptics_snapshot_helper" \
    "$source_root/haptics/baseline-20260614-daily-clean/testing-tools/y700-haptic-test.c"
  install -D -m 0644 "$haptics_build_source_path" \
    "$stage/build/aw86937-haptics.c"

  [ "$(sha256sum "$source_root/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c" | awk '{print $1}')" = "$haptics_driver_source_sha256" ] ||
    ci_die "staged AW86937 driver snapshot changed"
  [ "$(sha256sum "$stage/build/aw86937-haptics.c" | awk '{print $1}')" = "$haptics_build_source_sha256" ] ||
    ci_die "staged AW86937 build source changed"
  [ "$(sha256sum "$source_root/haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin" | awk '{print $1}')" = "$haptics_ram_firmware_sha256" ] ||
    ci_die "staged haptic_ram.bin changed"
  [ "$(sha256sum "$source_root/haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin" | awk '{print $1}')" = "$haptics_click_firmware_sha256" ] ||
    ci_die "staged haptic_click.bin changed"
  [ "$(sha256sum "$source_root/haptics/baseline-20260614-daily-clean/testing-tools/y700-haptic-test.c" | awk '{print $1}')" = "$haptics_test_helper_sha256" ] ||
    ci_die "staged haptics test helper source changed"
}

write_haptics_source_lock() {
  {
    printf 'schema\ttb321fu.haptics-source-lock/v1\n'
    printf 'haptics-producer-commit\t%s\n' "$haptics_producer_commit"
    printf 'haptics-producer-state\t%s\n' "$haptics_producer_state"
    printf 'aw86937-driver-sha256\t%s\n' "$haptics_driver_source_sha256"
    printf 'aw86937-build-source-sha256\t%s\n' "$haptics_build_source_sha256"
    printf 'haptic-ram-firmware-sha256\t%s\n' "$haptics_ram_firmware_sha256"
    printf 'haptic-click-firmware-sha256\t%s\n' "$haptics_click_firmware_sha256"
    printf 'haptic-test-helper-sha256\t%s\n' "$haptics_test_helper_sha256"
    printf 'aw86937-module-sha256\t%s\n' "$haptics_module_sha256"
    printf 'haptic-test-helper-binary-sha256\t%s\n' "$haptics_test_helper_binary_sha256"
    printf 'kernel-bundle-id\t%s\n' "$kernel_bundle_id"
    printf 'kernel-release\t%s\n' "$kernel_release"
    printf 'kernel-source-commit\t%s\n' "${EXPECTED_KERNEL_SOURCE_COMMIT:-unverified-local-source}"
    printf 'kernel-config-sha256\t%s\n' "$kernel_bundle_config_sha256"
    printf 'kernel-build-archive-sha256\t%s\n' "$kernel_build_archive_identity"
    printf 'source-date-epoch\t%s\n' "$SOURCE_DATE_EPOCH"
  } > "$OUTPUT_DIR/HAPTICS-SOURCE-LOCK.tsv"
}

write_haptics_checksums() {
  (
    cd "$OUTPUT_DIR"
    sha256sum \
      "./$haptics_deb_name" \
      ./HAPTICS-SOURCE-LOCK.tsv \
      ./HAPTICS-PRODUCER.bundle \
      ./HAPTICS-SOURCE-SNAPSHOT/source/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c \
      ./HAPTICS-SOURCE-SNAPSHOT/build/aw86937-haptics.c \
      ./HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin \
      ./HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin \
      ./HAPTICS-SOURCE-SNAPSHOT/source/haptics/baseline-20260614-daily-clean/testing-tools/y700-haptic-test.c \
      > SHA256SUMS-tb321fu-haptics-debs.txt
  )
}

finalize_haptics_output() {
  local index relative
  local manifest="$OUTPUT_DIR/SHA256SUMS-tb321fu-haptics-debs.txt"
  local -a expected_root=(
    HAPTICS-PRODUCER.bundle
    HAPTICS-SOURCE-LOCK.tsv
    HAPTICS-SOURCE-SNAPSHOT
    SHA256SUMS-tb321fu-haptics-debs.txt
    "$haptics_deb_name"
  )
  local -a actual_root=() expected_manifest=(
    "./$haptics_deb_name"
    ./HAPTICS-SOURCE-LOCK.tsv
    ./HAPTICS-PRODUCER.bundle
    ./HAPTICS-SOURCE-SNAPSHOT/source/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c
    ./HAPTICS-SOURCE-SNAPSHOT/build/aw86937-haptics.c
    ./HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin
    ./HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin
    ./HAPTICS-SOURCE-SNAPSHOT/source/haptics/baseline-20260614-daily-clean/testing-tools/y700-haptic-test.c
  ) actual_manifest=()

  mapfile -t actual_root < <(find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
  [ "${#actual_root[@]}" -eq "${#expected_root[@]}" ] ||
    ci_die "haptics output staging has an unexpected root entry count"
  for index in "${!expected_root[@]}"; do
    [ "${actual_root[$index]}" = "${expected_root[$index]}" ] ||
      ci_die "haptics output staging root mismatch: expected ${expected_root[$index]}, got ${actual_root[$index]}"
  done
  [ -z "$(find "$OUTPUT_DIR" -mindepth 1 ! -type d ! -type f -print -quit)" ] ||
    ci_die "haptics output staging contains a non-regular member"
  for relative in \
    "$haptics_deb_name" \
    HAPTICS-SOURCE-LOCK.tsv \
    HAPTICS-PRODUCER.bundle \
    SHA256SUMS-tb321fu-haptics-debs.txt; do
    [ -f "$OUTPUT_DIR/$relative" ] && [ ! -L "$OUTPUT_DIR/$relative" ] ||
      ci_die "haptics output file is not regular: $relative"
    [ "$(stat -c '%a' "$OUTPUT_DIR/$relative")" = 644 ] ||
      ci_die "haptics output file mode is not 0644: $relative"
  done

  mapfile -t actual_manifest < <(awk '{ print $2 }' "$manifest")
  [ "${#actual_manifest[@]}" -eq "${#expected_manifest[@]}" ] ||
    ci_die "haptics checksum manifest has an unexpected entry count"
  for index in "${!expected_manifest[@]}"; do
    [ "${actual_manifest[$index]}" = "${expected_manifest[$index]}" ] ||
      ci_die "haptics checksum manifest order mismatch: expected ${expected_manifest[$index]}, got ${actual_manifest[$index]}"
  done
  (cd "$OUTPUT_DIR" && sha256sum --strict -c SHA256SUMS-tb321fu-haptics-debs.txt >/dev/null)

  [ ! -e "$output_path" ] || ci_die "OUTPUT_DIR appeared during atomic promotion: $output_path"
  chmod 0755 "$OUTPUT_DIR"
  mv -T -- "$OUTPUT_DIR" "$output_path"
  output_stage=
  OUTPUT_DIR=$output_path
}

prepare_inputs
verify_haptics_producer_state "before package build"
prepare_haptics_source_snapshot
create_haptics_producer_bundle
prepare_kernel_host_tools
build_haptics_package
verify_kernel_source_state "after package build"
verify_haptics_producer_state "after package build"
verify_private_haptics_source_snapshot "before final source snapshot staging"
stage_haptics_source_snapshot
install -m 0644 "$producer_bundle" "$OUTPUT_DIR/HAPTICS-PRODUCER.bundle"
write_haptics_source_lock

ci_log "writing haptics package checksums"
write_haptics_checksums
finalize_haptics_output
ci_log "haptics package build complete: $OUTPUT_DIR"
