#!/usr/bin/env bash
set -euo pipefail

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

OUTPUT_DIR=${OUTPUT_DIR:-out/tb321fu-haptics-debs}
ARCH=${ARCH:-arm64}
HAPTICS_DEB_VERSION=${HAPTICS_DEB_VERSION:-20260627.1}
HAPTICS_SOURCE_ARCHIVE=${HAPTICS_SOURCE_ARCHIVE:-}
HAPTICS_SOURCE_ARCHIVE_SHA256=${HAPTICS_SOURCE_ARCHIVE_SHA256:-}
HAPTICS_SOURCE_DIR=${HAPTICS_SOURCE_DIR:-}
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
kernel_bundle_id=unbound
kernel_bundle_config_sha256=unbound

[ "$ARCH" = arm64 ] || ci_die "unsupported ARCH=$ARCH; only arm64 is supported"
[[ $HAPTICS_DEB_VERSION =~ ^[0-9][0-9A-Za-z.+~_-]{0,63}$ ]] || ci_die "unsafe HAPTICS_DEB_VERSION"
dpkg --validate-version "$HAPTICS_DEB_VERSION" >/dev/null || ci_die "invalid HAPTICS_DEB_VERSION"
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]{1,10}$ ]] || ci_die "invalid SOURCE_DATE_EPOCH"
if [ -n "$EXPECTED_KERNEL_SOURCE_COMMIT" ]; then
  [[ $EXPECTED_KERNEL_SOURCE_COMMIT =~ ^[0-9a-f]{40}$ ]] || ci_die "invalid EXPECTED_KERNEL_SOURCE_COMMIT"
  ci_require_cmd git
fi
export SOURCE_DATE_EPOCH

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR=$(ci_abs_path "$OUTPUT_DIR")
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/tb321fu-haptics-build.XXXXXX")

cleanup() {
  rm -rf "$work_dir"
}
trap cleanup EXIT

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
    local -a source_git
    if [ -n "$KERNEL_GIT_DIR" ]; then
      [ -d "$KERNEL_GIT_DIR/objects" ] || ci_die "KERNEL_GIT_DIR is not a Git object database"
      source_git=(git --git-dir="$KERNEL_GIT_DIR" --work-tree="$kernel_source_root")
    elif [ -d "$kernel_source_root/.git" ]; then
      source_git=(git -C "$kernel_source_root")
    else
      ci_die "kernel source lacks Git metadata for commit verification"
    fi
    actual_kernel_commit=$("${source_git[@]}" rev-parse HEAD)
    [ "$actual_kernel_commit" = "$EXPECTED_KERNEL_SOURCE_COMMIT" ] ||
      ci_die "kernel source commit mismatch: expected $EXPECTED_KERNEL_SOURCE_COMMIT, got $actual_kernel_commit"
    [ -z "$("${source_git[@]}" status --porcelain --untracked-files=all)" ] ||
      ci_die "kernel source must be clean for commit-bound haptics packaging"
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

kernel_make() {
  if [ -n "$KERNEL_GIT_DIR" ]; then
    env GIT_DIR="$KERNEL_GIT_DIR" GIT_WORK_TREE="$kernel_source_root" \
      make -C "$kernel_source_root" "$@"
  else
    make -C "$kernel_source_root" "$@"
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
  local helper_src="$haptics_root/haptics/baseline-20260614-daily-clean/testing-tools/y700-haptic-test.c"
  local source_sha256 build_source_sha256

  ci_log "building aw86937-haptics external module"
  mkdir -p "$src"
  cp -a "$haptics_root/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c" "$src/aw86937-haptics.c"
  source_sha256=$(sha256sum "$src/aw86937-haptics.c" | awk '{print $1}')
  [ "$source_sha256" = 2e0cb7b739496ff6cf4011244ec9c0b2a2367896de65784041018b9d62186e48 ] ||
    ci_die "AW86937 driver source does not match the canonical corrected source: $source_sha256"
  grep -q 'wait_event_timeout(haptics->play_wait' "$src/aw86937-haptics.c" ||
    ci_die "AW86937 driver lacks cancellable playback"
  grep -q 'pm_sleep_ptr(&aw86937_y700_pm_ops)' "$src/aw86937-haptics.c" ||
    ci_die "AW86937 driver lacks PM callbacks"
  if grep -Eq 'msleep\((duration_ms|play_ms)\)' "$src/aw86937-haptics.c"; then
    ci_die "AW86937 driver contains an uninterruptible effect wait"
  fi
  patch_source_for_standard_module_name "$src/aw86937-haptics.c"
  build_source_sha256=$(sha256sum "$src/aw86937-haptics.c" | awk '{print $1}')
  cat > "$src/Makefile" <<'EOF_MAKE'
obj-m := aw86937-haptics.o
EOF_MAKE

  kernel_make O="$kernel_build_root" ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- M="$src" modules
  [ -f "$module" ] || ci_die "missing built module: $module"
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
  install -m 0644 "$haptics_root/haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin" "$pkg/usr/lib/firmware/haptic_ram.bin"
  install -m 0644 "$haptics_root/haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin" "$pkg/usr/lib/firmware/haptic_click.bin"
  write_bind_script "$pkg/usr/libexec/tb321fu-haptics/bind-aw86937"
  write_systemd_unit "$pkg/usr/lib/systemd/system/tb321fu-haptics.service"
  write_udev_rules "$pkg/usr/lib/udev/rules.d/90-tb321fu-haptics.rules"
  write_plasma_keyboard_default "$pkg/etc/skel/.config/plasmakeyboardrc"

  if [ -f "$helper_src" ]; then
    aarch64-linux-gnu-gcc -O2 -Wall -Wextra -o "$pkg/usr/bin/tb321fu-haptic-test" "$helper_src"
    chmod 0755 "$pkg/usr/bin/tb321fu-haptic-test"
    strip_if_requested "$pkg/usr/bin/tb321fu-haptic-test"
  fi

  strip_if_requested "$pkg/usr/lib/modules/$kernel_release/extra/aw86937-haptics.ko"
  write_control "$pkg"
  write_maintainer_scripts "$pkg"

  find "$pkg" -type d -exec chmod 0755 {} +
  find "$pkg" -xdev -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  deb="$OUTPUT_DIR/tb321fu-haptics_${HAPTICS_DEB_VERSION}_${ARCH}.deb"
  dpkg-deb --build --root-owner-group "$pkg" "$deb" >/dev/null
  {
    printf 'aw86937-driver-sha256\t%s\n' "$source_sha256"
    printf 'aw86937-build-source-sha256\t%s\n' "$build_source_sha256"
    printf 'kernel-release\t%s\n' "$kernel_release"
    printf 'kernel-source-commit\t%s\n' "${EXPECTED_KERNEL_SOURCE_COMMIT:-unverified-local-source}"
    printf 'kernel-config-sha256\t%s\n' "$kernel_bundle_config_sha256"
    printf 'kernel-bundle-id\t%s\n' "$kernel_bundle_id"
    printf 'kernel-build-archive-sha256\t%s\n' "${KERNEL_BUILD_ARCHIVE_SHA256:-local-build-directory}"
    printf 'source-date-epoch\t%s\n' "$SOURCE_DATE_EPOCH"
  } > "$OUTPUT_DIR/HAPTICS-SOURCE-LOCK.tsv"
  sha256sum "$deb"
}

prepare_inputs
prepare_kernel_host_tools
build_haptics_package

ci_log "writing haptics package checksums"
(cd "$OUTPUT_DIR" && \
  sha256sum ./*.deb ./HAPTICS-SOURCE-LOCK.tsv > SHA256SUMS-tb321fu-haptics-debs.txt)
ci_log "haptics package build complete: $OUTPUT_DIR"
