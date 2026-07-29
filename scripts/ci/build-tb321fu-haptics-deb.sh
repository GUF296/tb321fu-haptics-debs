#!/bin/sh
if [ "${HAPTICS_BUILDER_CLEAN_ENV:-}" != 1 ] || [ -z "${BASH_VERSION:-}" ]; then
  script_path=$(/usr/bin/realpath -e -- "$0") || exit 1
  exec /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C LC_ALL=C TZ=UTC HOME=/nonexistent TMPDIR=/tmp \
    HAPTICS_BUILDER_CLEAN_ENV=1 \
    OUTPUT_DIR="${OUTPUT_DIR-}" \
    ARCH="${ARCH-}" \
    HAPTICS_DEB_VERSION="${HAPTICS_DEB_VERSION-}" \
    HAPTICS_SOURCE_ARCHIVE="${HAPTICS_SOURCE_ARCHIVE-}" \
    HAPTICS_SOURCE_ARCHIVE_SHA256="${HAPTICS_SOURCE_ARCHIVE_SHA256-}" \
    HAPTICS_SOURCE_DIR="${HAPTICS_SOURCE_DIR-}" \
    HAPTICS_GIT_DIR="${HAPTICS_GIT_DIR-}" \
    EXPECTED_HAPTICS_PRODUCER_COMMIT="${EXPECTED_HAPTICS_PRODUCER_COMMIT-}" \
    KERNEL_SOURCE_ARCHIVE="${KERNEL_SOURCE_ARCHIVE-}" \
    KERNEL_SOURCE_ARCHIVE_SHA256="${KERNEL_SOURCE_ARCHIVE_SHA256-}" \
    KERNEL_SOURCE_DIR="${KERNEL_SOURCE_DIR-}" \
    KERNEL_BUILD_ARCHIVE="${KERNEL_BUILD_ARCHIVE-}" \
    KERNEL_BUILD_ARCHIVE_SHA256="${KERNEL_BUILD_ARCHIVE_SHA256-}" \
    KERNEL_BUILD_DIR="${KERNEL_BUILD_DIR-}" \
    KERNEL_GIT_DIR="${KERNEL_GIT_DIR-}" \
    KERNEL_BUNDLE_METADATA="${KERNEL_BUNDLE_METADATA-}" \
    KERNEL_BUNDLE_METADATA_SHA256="${KERNEL_BUNDLE_METADATA_SHA256-}" \
    KERNEL_SDK_MANIFEST="${KERNEL_SDK_MANIFEST-}" \
    EXPECTED_KERNEL_SOURCE_COMMIT="${EXPECTED_KERNEL_SOURCE_COMMIT-}" \
    HAPTICS_STRIP="${HAPTICS_STRIP-}" \
    HAPTICS_RELEASE_MODE="${HAPTICS_RELEASE_MODE-}" \
    SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH-}" \
    EXPECTED_HAPTICS_BUILD_TOOLSET_SHA256="${EXPECTED_HAPTICS_BUILD_TOOLSET_SHA256-}" \
    EXPECTED_HAPTICS_BUILD_ENVIRONMENT_POLICY_SHA256="${EXPECTED_HAPTICS_BUILD_ENVIRONMENT_POLICY_SHA256-}" \
    http_proxy="${http_proxy-}" HTTP_PROXY="${HTTP_PROXY-}" \
    https_proxy="${https_proxy-}" HTTPS_PROXY="${HTTPS_PROXY-}" \
    no_proxy="${no_proxy-}" NO_PROXY="${NO_PROXY-}" \
    /usr/bin/bash --noprofile --norc "$script_path" "$@"
fi
SCRIPT_SOURCE=${BASH_SOURCE[0]}
case "$SCRIPT_SOURCE" in
  /*) SCRIPT_PATH=$SCRIPT_SOURCE ;;
  */*) SCRIPT_PATH=$(cd -P -- "${SCRIPT_SOURCE%/*}" && printf '%s/%s\n' "$PWD" "${SCRIPT_SOURCE##*/}") ;;
  *) SCRIPT_PATH=$PWD/$SCRIPT_SOURCE ;;
esac
SCRIPT_DIR=${SCRIPT_PATH%/*}
. "$SCRIPT_DIR/common.sh"
. "$SCRIPT_DIR/haptics-build-environment.sh"
. "$SCRIPT_DIR/haptics-maintainer-scripts.sh"
. "$SCRIPT_DIR/haptics-kernel-sdk-contract.sh"

haptics_enter_clean_environment HAPTICS_BUILDER_CLEAN_ENV "$SCRIPT_PATH" \
  OUTPUT_DIR \
  ARCH \
  HAPTICS_DEB_VERSION \
  HAPTICS_SOURCE_ARCHIVE \
  HAPTICS_SOURCE_ARCHIVE_SHA256 \
  HAPTICS_SOURCE_DIR \
  HAPTICS_GIT_DIR \
  EXPECTED_HAPTICS_PRODUCER_COMMIT \
  KERNEL_SOURCE_ARCHIVE \
  KERNEL_SOURCE_ARCHIVE_SHA256 \
  KERNEL_SOURCE_DIR \
  KERNEL_BUILD_ARCHIVE \
  KERNEL_BUILD_ARCHIVE_SHA256 \
  KERNEL_BUILD_DIR \
  KERNEL_GIT_DIR \
  KERNEL_BUNDLE_METADATA \
  KERNEL_BUNDLE_METADATA_SHA256 \
  KERNEL_SDK_MANIFEST \
  EXPECTED_KERNEL_SOURCE_COMMIT \
  HAPTICS_STRIP \
  HAPTICS_RELEASE_MODE \
  SOURCE_DATE_EPOCH \
  EXPECTED_HAPTICS_BUILD_TOOLSET_SHA256 \
  EXPECTED_HAPTICS_BUILD_ENVIRONMENT_POLICY_SHA256 \
  -- "$@"

set -euo pipefail
umask 022

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
  KERNEL_SDK_MANIFEST        external KERNEL-SDK-MANIFEST.tsv path or HTTPS URL
  EXPECTED_KERNEL_SOURCE_COMMIT
                              optional exact 40-hex source identity
  HAPTICS_RELEASE_MODE        1 requires a portable, archive-bound release candidate;
                              0 permits a nonportable local KERNEL_BUILD_DIR build
  SOURCE_DATE_EPOCH          reproducible build timestamp
  HAPTICS_STRIP              strip binaries/modules after build, default: 0
USAGE
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  exit 0
fi

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
KERNEL_SDK_MANIFEST=${KERNEL_SDK_MANIFEST:-}
EXPECTED_KERNEL_SOURCE_COMMIT=${EXPECTED_KERNEL_SOURCE_COMMIT:-}
HAPTICS_STRIP=${HAPTICS_STRIP:-0}
HAPTICS_RELEASE_MODE=${HAPTICS_RELEASE_MODE:-0}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
EXPECTED_HAPTICS_BUILD_TOOLSET_SHA256=${EXPECTED_HAPTICS_BUILD_TOOLSET_SHA256:-}
EXPECTED_HAPTICS_BUILD_ENVIRONMENT_POLICY_SHA256=${EXPECTED_HAPTICS_BUILD_ENVIRONMENT_POLICY_SHA256:-}
kernel_build_archive_identity=local-build-directory
kernel_build_input=local-directory
kernel_bundle_id=unbound
kernel_bundle_config_sha256=unbound
kernel_bundle_sdk_archive_sha256=unbound
kernel_bundle_sdk_manifest_sha256=unbound
kernel_sdk_manifest_path=
haptics_source_lock_schema=
haptics_output_mode=
build_tools_manifest_sha256=

[ "$ARCH" = arm64 ] || ci_die "unsupported ARCH=$ARCH; only arm64 is supported"
[[ $HAPTICS_DEB_VERSION =~ ^[0-9][0-9A-Za-z.+~_-]{0,63}$ ]] || ci_die "unsafe HAPTICS_DEB_VERSION"
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]{1,10}$ ]] || ci_die "invalid SOURCE_DATE_EPOCH"
[[ $EXPECTED_HAPTICS_PRODUCER_COMMIT =~ ^[0-9a-f]{40}$ ]] ||
  ci_die "EXPECTED_HAPTICS_PRODUCER_COMMIT must be 40 lowercase hex characters"
haptics_capture_build_tools
haptics_verify_expected_build_environment
haptics_run_isolated_tool dpkg --validate-version "$HAPTICS_DEB_VERSION" >/dev/null ||
  ci_die "invalid HAPTICS_DEB_VERSION"
haptics_validate_kernel_build_input_contract \
  "$HAPTICS_RELEASE_MODE" \
  "$KERNEL_BUILD_ARCHIVE" \
  "$KERNEL_BUILD_ARCHIVE_SHA256" \
  "$KERNEL_BUILD_DIR" \
  "$KERNEL_BUNDLE_METADATA" \
  "$KERNEL_BUNDLE_METADATA_SHA256" \
  "$KERNEL_SDK_MANIFEST"
if [ "$HAPTICS_RELEASE_MODE" = 1 ]; then
  haptics_source_lock_schema=tb321fu.haptics-source-lock/v3
  haptics_output_mode=release-candidate
else
  haptics_source_lock_schema=tb321fu.haptics-source-lock/v3-local
  haptics_output_mode=local
fi
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
kernel_fixdep_path=
kernel_fixdep_sha256=
kernel_modpost_path=
kernel_modpost_sha256=

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
haptics_kbuild_path="$work_dir/kbuild-tools"
haptics_prepare_kbuild_tool_path "$haptics_kbuild_path"

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

copy_kernel_build_dir_private() {
  local source_dir=$1 private_dir=$2 private_root source_link candidate resolved
  local kernel_source_real special

  source_dir=$(realpath -e -- "$source_dir") ||
    ci_die "cannot resolve KERNEL_BUILD_DIR: $1"
  [ -d "$source_dir" ] || ci_die "KERNEL_BUILD_DIR is not a directory: $source_dir"
  find_kernel_build_root "$source_dir" >/dev/null ||
    ci_die "KERNEL_BUILD_DIR does not contain kernel build output"
  special=$(find "$source_dir" -xdev \
    \( -type b -o -type c -o -type p -o -type s \) -print -quit)
  [ -z "$special" ] ||
    ci_die "KERNEL_BUILD_DIR contains an unsupported special file: $special"
  kernel_source_real=$(realpath -e -- "$kernel_source_root") ||
    ci_die "cannot resolve kernel source root for private build copy"

  ci_log "copying KERNEL_BUILD_DIR into private build workspace" >&2
  mkdir -p "$private_dir"
  # Do not use reflinks or hardlinks: host-tool regeneration must never mutate
  # the caller's build output through a shared inode.
  haptics_run_isolated_tool rsync -a --links --no-specials --no-devices -- \
    "$source_dir/" "$private_dir/"
  private_root=$(find_kernel_build_root "$private_dir") ||
    ci_die "private KERNEL_BUILD_DIR copy does not contain kernel build output"

  # Kernel O= trees normally keep this link to their source tree. Recreate
  # only that known link for the separately verified source input, then reject
  # every other link that escapes the private copy.
  source_link="$private_root/source"
  if [ -L "$source_link" ]; then
    rm -f -- "$source_link"
    ln -s -- "$kernel_source_real" "$source_link"
  fi
  while IFS= read -r -d '' candidate; do
    resolved=$(realpath -e -- "$candidate") ||
      ci_die "private KERNEL_BUILD_DIR contains a dangling symlink: $candidate"
    if [ "$candidate" = "$source_link" ]; then
      [ "$resolved" = "$kernel_source_real" ] ||
        ci_die "private kernel source link does not target the verified source"
      continue
    fi
    case "$resolved" in
      "$private_dir"|"$private_dir"/*) ;;
      *) ci_die "private KERNEL_BUILD_DIR contains an external symlink: $candidate" ;;
    esac
  done < <(find "$private_dir" -type l -print0)

  printf '%s\n' "$private_root"
}

load_kernel_bundle_metadata() {
  local metadata="$work_dir/KERNEL-BUNDLE.tsv"
  local canonical="$work_dir/KERNEL-BUNDLE.canonical.tsv"
  local -a verify_args

  [ -n "$KERNEL_BUNDLE_METADATA" ] || return 0
  ci_download "$KERNEL_BUNDLE_METADATA" "$metadata" "$KERNEL_BUNDLE_METADATA_SHA256"
  verify_args=("$metadata" --emit-tsv)
  if [ -n "$EXPECTED_KERNEL_SOURCE_COMMIT" ]; then
    verify_args+=(--expect "kernel-source-commit=$EXPECTED_KERNEL_SOURCE_COMMIT")
  fi
  haptics_run_isolated_tool python3 \
    "$SCRIPT_DIR/verify-kernel-bundle.py" "${verify_args[@]}" > "$canonical" ||
    ci_die "invalid KERNEL-BUNDLE.tsv"

  kernel_bundle_value() {
    local key=$1 value count

    count=$(awk -F '\t' -v key="$key" '$1 == key { count++ } END { print count + 0 }' "$canonical")
    [ "$count" -eq 1 ] || ci_die "KERNEL-BUNDLE.tsv must contain exactly one $key"
    value=$(awk -F '\t' -v key="$key" '$1 == key { print $2 }' "$canonical")
    printf '%s\n' "$value"
  }

  kernel_bundle_commit=$(kernel_bundle_value kernel-source-commit)
  kernel_bundle_release=$(kernel_bundle_value kernel-release)
  kernel_bundle_config_sha256=$(kernel_bundle_value kernel-config-sha256)
  kernel_bundle_sdk_archive_sha256=$(kernel_bundle_value kernel-sdk-archive-sha256)
  kernel_bundle_sdk_manifest_sha256=$(kernel_bundle_value kernel-sdk-manifest-sha256)
  kernel_bundle_epoch=$(kernel_bundle_value source-date-epoch)
  kernel_bundle_id=$(kernel_bundle_value kernel-bundle-id)

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

  load_kernel_bundle_metadata
  if [ -n "$KERNEL_BUILD_DIR" ]; then
    kernel_build_root=$(copy_kernel_build_dir_private \
      "$KERNEL_BUILD_DIR" "$work_dir/kernel-build-private")
  else
    [ -n "$KERNEL_BUILD_ARCHIVE" ] || ci_die "set KERNEL_BUILD_ARCHIVE or KERNEL_BUILD_DIR"
    archive="$work_dir/kernel-build.archive"
    extract="$work_dir/kernel-build"
    ci_download "$KERNEL_BUILD_ARCHIVE" "$archive" "$KERNEL_BUILD_ARCHIVE_SHA256"
    kernel_build_archive_identity=$(haptics_sha256_file "$archive")
    kernel_build_input=kernel-sdk-archive
    haptics_validate_kernel_sdk_binding \
      "$HAPTICS_RELEASE_MODE" \
      "$kernel_build_input" \
      "$kernel_build_archive_identity" \
      "$kernel_bundle_id" \
      "$kernel_bundle_sdk_archive_sha256"
    if [ "$kernel_bundle_id" != unbound ]; then
      [ -n "$KERNEL_SDK_MANIFEST" ] ||
        ci_die "KERNEL-BUNDLE.tsv requires KERNEL_SDK_MANIFEST for an SDK archive"
      kernel_sdk_manifest_path="$work_dir/KERNEL-SDK-MANIFEST.tsv"
      ci_download "$KERNEL_SDK_MANIFEST" "$kernel_sdk_manifest_path" \
        "$kernel_bundle_sdk_manifest_sha256"
    fi
    if [ -n "$kernel_sdk_manifest_path" ]; then
      haptics_run_isolated_tool python3 "$SCRIPT_DIR/verify-kernel-sdk.py" --archive-only \
        "$archive" "$kernel_sdk_manifest_path" ||
        ci_die "kernel SDK archive does not match KERNEL-SDK-MANIFEST.tsv"
    fi
    ci_extract_archive "$archive" "$extract"
    if [ -n "$kernel_sdk_manifest_path" ]; then
      haptics_run_isolated_tool python3 "$SCRIPT_DIR/verify-kernel-sdk.py" \
        "$archive" "$kernel_sdk_manifest_path" "$extract" ||
        ci_die "kernel SDK archive does not match KERNEL-SDK-MANIFEST.tsv"
      kernel_build_root="$extract"
    else
      kernel_build_root=$(find_kernel_build_root "$extract") || ci_die "KERNEL_BUILD_ARCHIVE does not contain kernel build output"
    fi
  fi

  kernel_release=$(cat "$kernel_build_root/include/config/kernel.release")
  haptics_validate_kernel_release "$kernel_release" ||
    ci_die "unsafe kernel release from kernel build output: $kernel_release"
  if [ "$kernel_bundle_id" != unbound ]; then
    [ "$kernel_release" = "$kernel_bundle_release" ] || ci_die "kernel release differs from KERNEL-BUNDLE.tsv"
    [ "$(haptics_sha256_file "$kernel_build_root/.config")" = "$kernel_bundle_config_sha256" ] ||
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

validate_haptics_maintainer_source_contract() {
  local contract_root="$work_dir/haptics-maintainer-contract"
  local helper="$contract_root/scripts/ci/haptics-maintainer-scripts.sh"
  local relative exported local_path token template rendered
  local -a required=(
    scripts/ci/haptics-maintainer-scripts.sh
    scripts/ci/haptics-control-templates/postinst.in
    scripts/ci/haptics-control-templates/prerm.in
    scripts/ci/haptics-control-templates/postrm.in
  )

  [ "$(realpath -e -- "$SCRIPT_DIR")" = \
    "$(realpath -e -- "$haptics_root/scripts/ci")" ] ||
    ci_die "haptics maintainer scripts are not from the verified producer root"
  for relative in "${required[@]}"; do
    local_path="$haptics_root/$relative"
    exported="$contract_root/$relative"
    [ -f "$local_path" ] && [ ! -L "$local_path" ] ||
      ci_die "missing regular haptics maintainer contract file: $relative"
    ci_export_git_file "$haptics_root" "$EXPECTED_HAPTICS_PRODUCER_COMMIT" \
      "$relative" "$exported" "$HAPTICS_GIT_DIR"
    cmp -s "$local_path" "$exported" ||
      ci_die "haptics maintainer contract differs from the verified producer commit: $relative"
  done

  bash -n "$helper" ||
    ci_die "haptics maintainer helper has invalid Bash syntax"
  if grep -Fq 'HAPTICS_MAINTAINER_TEMPLATE_DIR=${' "$helper"; then
    ci_die "haptics maintainer helper must not allow an environment template override"
  fi
  grep -Fq '$(dirname -- "${BASH_SOURCE[0]}")/haptics-control-templates' "$helper" ||
    ci_die "haptics maintainer helper must derive templates from its committed location"
  for token in \
    haptics_validate_kernel_release \
    haptics_render_maintainer_template \
    haptics_write_maintainer_scripts \
    HAPTICS_MAINTAINER_TEMPLATE_DIR; do
    grep -Fq -- "$token" "$helper" ||
      ci_die "haptics maintainer helper lacks required contract token: $token"
  done
  for template in postinst prerm postrm; do
    rendered="$contract_root/rendered-$template"
    haptics_render_maintainer_template \
      "$contract_root/scripts/ci/haptics-control-templates/$template.in" \
      "$rendered" "$kernel_release" ||
      ci_die "cannot render verified haptics maintainer template: $template"
  done
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
    actual_config_sha256=$(haptics_sha256_file "$kernel_build_root/.config")
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
  haptics_driver_source_sha256=$(haptics_sha256_file "$haptics_snapshot_driver")
  haptics_ram_firmware_sha256=$(haptics_sha256_file "$haptics_snapshot_ram_firmware")
  haptics_click_firmware_sha256=$(haptics_sha256_file "$haptics_snapshot_click_firmware")
  haptics_test_helper_sha256=$(haptics_sha256_file "$haptics_snapshot_helper")
  [ "$haptics_driver_source_sha256" = 31342e17cb20c73755623542fdac4fa1e185cb2b123d798f2f7b8024a630d457 ] ||
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
  [ "$(haptics_sha256_file "$haptics_snapshot_driver")" = "$haptics_driver_source_sha256" ] ||
    ci_die "private AW86937 driver snapshot changed $label"
  [ "$(haptics_sha256_file "$haptics_snapshot_ram_firmware")" = "$haptics_ram_firmware_sha256" ] ||
    ci_die "private haptic_ram.bin snapshot changed $label"
  [ "$(haptics_sha256_file "$haptics_snapshot_click_firmware")" = "$haptics_click_firmware_sha256" ] ||
    ci_die "private haptic_click.bin snapshot changed $label"
  [ "$(haptics_sha256_file "$haptics_snapshot_helper")" = "$haptics_test_helper_sha256" ] ||
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
  local status
  local -a make_env=(
    "PATH=$haptics_kbuild_path"
    LANG=C
    LC_ALL=C
    TZ=UTC
    "HOME=$HAPTICS_BUILD_HOME"
    "TMPDIR=$HAPTICS_BUILD_TMPDIR"
    "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
    GIT_CONFIG_NOSYSTEM=1
    GIT_CONFIG_GLOBAL=/dev/null
    GIT_ATTR_NOSYSTEM=1
    GIT_OPTIONAL_LOCKS=0
    GIT_TERMINAL_PROMPT=0
    GIT_NO_REPLACE_OBJECTS=1
    GIT_CONFIG_COUNT=3
    GIT_CONFIG_KEY_0=core.fsmonitor
    GIT_CONFIG_VALUE_0=false
    GIT_CONFIG_KEY_1=core.untrackedCache
    GIT_CONFIG_VALUE_1=false
    GIT_CONFIG_KEY_2=core.excludesFile
    GIT_CONFIG_VALUE_2=/dev/null
    "CONFIG_SHELL=${HAPTICS_BUILD_TOOL_PATHS[dash]}"
    "SHELL=${HAPTICS_BUILD_TOOL_PATHS[dash]}"
  )

  if [ -n "$KERNEL_GIT_DIR" ]; then
    make_env+=("GIT_DIR=$KERNEL_GIT_DIR" "GIT_WORK_TREE=$kernel_source_root")
  fi
  haptics_verify_build_tools_unchanged "before Kbuild invocation"
  haptics_verify_kbuild_tool_path "$haptics_kbuild_path"
  if "${HAPTICS_BUILD_TOOL_PATHS[env]}" -i "${make_env[@]}" \
      "${HAPTICS_BUILD_TOOL_PATHS[make]}" -C "$kernel_source_root" "$@" \
      ARCH=arm64 \
      CONFIG_SHELL="${HAPTICS_BUILD_TOOL_PATHS[dash]}" \
      SHELL="${HAPTICS_BUILD_TOOL_PATHS[dash]}" \
      HOSTCC="${HAPTICS_BUILD_TOOL_PATHS[gcc]}" \
      HOSTAS="${HAPTICS_BUILD_TOOL_PATHS[as]}" \
      HOSTLD="${HAPTICS_BUILD_TOOL_PATHS[ld]}" \
      HOSTAR="${HAPTICS_BUILD_TOOL_PATHS[ar]}" \
      CROSS_COMPILE= \
      CC="${HAPTICS_BUILD_TOOL_PATHS[aarch64-linux-gnu-gcc]}" \
      CPP="${HAPTICS_BUILD_TOOL_PATHS[aarch64-linux-gnu-cpp]}" \
      AS="${HAPTICS_BUILD_TOOL_PATHS[aarch64-linux-gnu-as]}" \
      LD="${HAPTICS_BUILD_TOOL_PATHS[aarch64-linux-gnu-ld]}" \
      AR="${HAPTICS_BUILD_TOOL_PATHS[aarch64-linux-gnu-ar]}" \
      NM="${HAPTICS_BUILD_TOOL_PATHS[aarch64-linux-gnu-nm]}" \
      OBJCOPY="${HAPTICS_BUILD_TOOL_PATHS[aarch64-linux-gnu-objcopy]}" \
      OBJDUMP="${HAPTICS_BUILD_TOOL_PATHS[aarch64-linux-gnu-objdump]}" \
      READELF="${HAPTICS_BUILD_TOOL_PATHS[aarch64-linux-gnu-readelf]}" \
      STRIP="${HAPTICS_BUILD_TOOL_PATHS[aarch64-linux-gnu-strip]}"; then
    status=0
  else
    status=$?
  fi
  haptics_verify_kbuild_tool_path "$haptics_kbuild_path"
  haptics_verify_build_tools_unchanged "after Kbuild invocation"
  return "$status"
}

record_kernel_host_tools() {
  local path

  kernel_fixdep_path=$(realpath -e -- "$kernel_build_root/scripts/basic/fixdep") ||
    ci_die "cannot resolve rebuilt kernel host tool: scripts/basic/fixdep"
  kernel_modpost_path=$(realpath -e -- "$kernel_build_root/scripts/mod/modpost") ||
    ci_die "cannot resolve rebuilt kernel host tool: scripts/mod/modpost"
  for path in "$kernel_fixdep_path" "$kernel_modpost_path"; do
    [ -f "$path" ] && [ -x "$path" ] && [ ! -L "$path" ] ||
      ci_die "rebuilt kernel host tool is not an absolute regular executable: $path"
  done
  kernel_fixdep_sha256=$(haptics_sha256_file "$kernel_fixdep_path")
  kernel_modpost_sha256=$(haptics_sha256_file "$kernel_modpost_path")
  ci_log "generated build tool: kernel-fixdep $kernel_fixdep_path $kernel_fixdep_sha256"
  ci_log "generated build tool: kernel-modpost $kernel_modpost_path $kernel_modpost_sha256"
}

verify_kernel_host_tools_unchanged() {
  local phase=$1

  [ -n "$kernel_fixdep_sha256" ] && [ -n "$kernel_modpost_sha256" ] ||
    ci_die "kernel host-tool evidence is missing $phase"
  [ "$(haptics_sha256_file "$kernel_fixdep_path")" = "$kernel_fixdep_sha256" ] ||
    ci_die "kernel fixdep bytes changed $phase"
  [ "$(haptics_sha256_file "$kernel_modpost_path")" = "$kernel_modpost_sha256" ] ||
    ci_die "kernel modpost bytes changed $phase"
  ci_log "generated kernel host tools unchanged $phase"
}

prepare_kernel_host_tools() {
  # Kernel build output archives can contain host tools from the machine that
  # prepared the SDK. Rebuild them on the current runner before external module
  # compilation so the SDK works on both x86_64 and arm64 hosts.
  rm -f \
    "$kernel_build_root/scripts/basic/fixdep" \
    "$kernel_build_root/scripts/mod/modpost"
  kernel_make O="$kernel_build_root" \
    scripts_basic scripts/mod/

  [ -x "$kernel_build_root/scripts/basic/fixdep" ] || ci_die "missing rebuilt kernel host tool: scripts/basic/fixdep"
  [ -x "$kernel_build_root/scripts/mod/modpost" ] || ci_die "missing rebuilt kernel host tool: scripts/mod/modpost"
  record_kernel_host_tools
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

  # Source-built kernel releases do not reliably map to a distro kernel package
  # version. postinst verifies the module's embedded vermagic instead.
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

write_bind_script() {
  local dest=$1

  cat > "$dest" <<'EOF_BIND'
#!/bin/sh
set -eu

SYSFS_ROOT=${TB321FU_HAPTICS_SYSFS_ROOT:-/sys}
case "$SYSFS_ROOT" in
	/*) ;;
	*) echo "TB321FU_HAPTICS_SYSFS_ROOT must be an absolute path" >&2; exit 1 ;;
esac
SYSFS_ROOT=${SYSFS_ROOT%/}
[ -n "$SYSFS_ROOT" ] || SYSFS_ROOT=/
I2C_DEVICES="$SYSFS_ROOT/bus/i2c/devices"
I2C_DRIVERS="$SYSFS_ROOT/bus/i2c/drivers"

compatible_contains()
{
	tr '\000' '\n' < "$1" | grep -Fxq "$2"
}

find_current_dt_client()
{
	address=$1
	target_client=
	target_problem=
	matches=0
	for dev in "$I2C_DEVICES"/*-"$address"; do
		[ -e "$dev" ] || continue
		if [ -r "$dev/of_node/compatible" ] && \
			compatible_contains "$dev/of_node/compatible" "lenovo,tb321fu-aw86937" && \
			compatible_contains "$dev/of_node/compatible" "awinic,aw86937"; then
			matches=$((matches + 1))
			target_client=$dev
		else
			target_problem=$dev
		fi
	done
	case "$matches" in
		1) return 0 ;;
		0)
			[ -n "$target_problem" ] && return 3
			return 1
			;;
		*)
			echo "multiple TB321FU AW86937 DT clients found for I2C address $address" >&2
			return 2
			;;
	esac
}

wait_for_target_pair()
{
	attempt=0
	right_problem=
	left_problem=
	while [ "$attempt" -lt 80 ]; do
		attempt=$((attempt + 1))
		right_client=
		left_client=
		if find_current_dt_client 005a; then
			right_client=$target_client
			right_status=0
		else
			right_status=$?
			right_problem=$target_problem
		fi
		if find_current_dt_client 005b; then
			left_client=$target_client
			left_status=0
		else
			left_status=$?
			left_problem=$target_problem
		fi
		[ "$right_status" -ne 2 ] && [ "$left_status" -ne 2 ] || return 1
		if [ "$right_status" -eq 0 ] && [ "$left_status" -eq 0 ]; then
			return 0
		fi
		sleep 0.25
	done
	if [ -n "$right_problem" ]; then
		echo "$right_problem is not a current TB321FU AW86937 DT client" >&2
		return 1
	fi
	if [ -n "$left_problem" ]; then
		echo "$left_problem is not a current TB321FU AW86937 DT client" >&2
		return 1
	fi
	echo "TB321FU AW86937 DT client pair (-005a and -005b) not found" >&2
	return 1
}

module_loaded()
{
	lsmod | awk 'NR > 1 { print $1 }' | grep -Fxq "$1"
}

load_current_driver()
{
	if module_loaded aw86937_y700; then
		echo "legacy aw86937_y700 module is already loaded; reboot before binding TB321FU haptics" >&2
		return 1
	fi
	module_loaded aw86937_haptics && return 0
	modprobe aw86937_haptics 2>/dev/null && return 0

	krel=$(uname -r)
	for module_path in \
		"/lib/modules/$krel/extra/aw86937-haptics.ko" \
		"/usr/lib/modules/$krel/extra/aw86937-haptics.ko"; do
		[ -f "$module_path" ] || continue
		insmod "$module_path" && return 0
	done

	echo "no current AW86937 haptics module could be loaded" >&2
	return 1
}

wait_for_current_driver()
{
	driver_dir="$I2C_DRIVERS/aw86937-haptics"
	attempt=0
	while [ "$attempt" -lt 40 ]; do
		[ -d "$driver_dir" ] && { printf '%s\n' "$driver_dir"; return 0; }
		attempt=$((attempt + 1))
		sleep 0.1
	done
	echo "current AW86937 haptics I2C driver is not registered" >&2
	return 1
}

bind_current_client()
{
	dev=$1
	driver_dir=$2
	busdev=$(basename "$dev")

	if [ -e "$dev/driver" ]; then
		driver=$(basename "$(readlink -f "$dev/driver")")
		[ "$driver" = aw86937-haptics ] && return 0
		echo "$dev is already bound to unexpected driver $driver" >&2
		return 1
	fi

	printf '%s\n' "$busdev" > "$driver_dir/bind" || {
		echo "cannot bind $dev to current AW86937 haptics driver" >&2
		return 1
	}
	attempt=0
	while [ "$attempt" -lt 20 ]; do
		if [ -e "$dev/driver" ]; then
			driver=$(basename "$(readlink -f "$dev/driver")")
			[ "$driver" = aw86937-haptics ] && return 0
			echo "$dev bound to unexpected driver $driver" >&2
			return 1
		fi
		attempt=$((attempt + 1))
		sleep 0.1
	done
	echo "$dev did not bind to current AW86937 haptics driver" >&2
	return 1
}

wait_for_target_pair || exit 1
load_current_driver || exit 1
driver_dir=$(wait_for_current_driver) || exit 1
bind_current_client "$right_client" "$driver_dir" || exit 1
bind_current_client "$left_client" "$driver_dir" || exit 1
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
SUBSYSTEM=="input", KERNEL=="event*", ATTRS{name}=="aw86937-haptics-left", GROUP="input", MODE="0660", TAG+="uaccess", ENV{FEEDBACKD_TYPE}="vibra", SYMLINK+="input/tb321fu-haptics-left"
SUBSYSTEM=="input", KERNEL=="event*", ATTRS{name}=="aw86937-haptics-right", GROUP="input", MODE="0660", TAG+="uaccess", ENV{FEEDBACKD_TYPE}="vibra", SYMLINK+="input/tb321fu-haptics-right"
LABEL="tb321fu_haptics_end"
EOF_UDEV
  chmod 0644 "$dest"
}

write_legacy_module_blacklist() {
  local dest=$1

  cat > "$dest" <<'EOF_MODPROBE'
# The in-tree module shares the TB321FU AW86937 OF aliases. Keep it from
# claiming DT-created clients before the package's current module is loaded.
blacklist aw86937_y700
EOF_MODPROBE
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
  haptics_run_isolated_tool aarch64-linux-gnu-strip --strip-unneeded "$@"
}

build_haptics_package() {
  local src="$work_dir/module-src"
  local pkg="$work_dir/pkg/tb321fu-haptics"
  local module="$src/aw86937-haptics.ko"
  local module_prefix=/usr/src/tb321fu-haptics
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
  [ "$(haptics_sha256_file "$src/aw86937-haptics.c")" = "$haptics_driver_source_sha256" ] ||
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
  haptics_build_source_sha256=$(haptics_sha256_file "$haptics_build_source_path")
  cat > "$src/Makefile" <<'EOF_MAKE'
obj-m := aw86937-haptics.o
EOF_MAKE

  verify_kernel_host_tools_unchanged "before external module build"
  kernel_make O="$kernel_build_root" \
    KCFLAGS="-fdebug-prefix-map=$src=$module_prefix -ffile-prefix-map=$src=$module_prefix -fmacro-prefix-map=$src=$module_prefix" \
    M="$src" modules
  verify_kernel_host_tools_unchanged "after external module build"
  verify_kernel_build_state "after external module build"
  [ -f "$module" ] || ci_die "missing built module: $module"
  [ "$(haptics_sha256_file "$haptics_build_source_path")" = "$haptics_build_source_sha256" ] ||
    ci_die "patched AW86937 build source changed during module compilation"
  haptics_run_isolated_tool kmod modinfo "$module" | tee "$work_dir/aw86937-haptics.modinfo"
  grep -q '^name:[[:space:]]*aw86937_haptics$' "$work_dir/aw86937-haptics.modinfo" || ci_die "unexpected module name"
  grep -q '^alias:[[:space:]]*i2c:aw86937_haptics$' "$work_dir/aw86937-haptics.modinfo" || ci_die "missing standard i2c alias"
  grep -Eq '^alias:[[:space:]]*of:.*lenovo,tb321fu-aw86937' "$work_dir/aw86937-haptics.modinfo" ||
    ci_die "missing TB321FU AW86937 OF alias"
  grep -Eq '^alias:[[:space:]]*of:.*awinic,aw86937' "$work_dir/aw86937-haptics.modinfo" ||
    ci_die "missing Awinic AW86937 OF alias"
  grep -q "^vermagic:[[:space:]]*$kernel_release " "$work_dir/aw86937-haptics.modinfo" || ci_die "module vermagic does not match $kernel_release"

  install -d -m 0755 \
    "$pkg/usr/lib/modules/$kernel_release/extra" \
    "$pkg/usr/lib/firmware" \
    "$pkg/usr/libexec/tb321fu-haptics" \
    "$pkg/usr/lib/systemd/system" \
    "$pkg/usr/lib/udev/rules.d" \
    "$pkg/etc/modprobe.d" \
    "$pkg/etc/skel/.config" \
    "$pkg/usr/bin"

  install -m 0644 "$module" "$pkg/usr/lib/modules/$kernel_release/extra/aw86937-haptics.ko"
  install -m 0644 "$ram_firmware" "$pkg/usr/lib/firmware/haptic_ram.bin"
  install -m 0644 "$click_firmware" "$pkg/usr/lib/firmware/haptic_click.bin"
  [ "$(haptics_sha256_file "$pkg/usr/lib/firmware/haptic_ram.bin")" = "$haptics_ram_firmware_sha256" ] ||
    ci_die "packaged haptic_ram.bin differs from the Git-object snapshot"
  [ "$(haptics_sha256_file "$pkg/usr/lib/firmware/haptic_click.bin")" = "$haptics_click_firmware_sha256" ] ||
    ci_die "packaged haptic_click.bin differs from the Git-object snapshot"
  write_bind_script "$pkg/usr/libexec/tb321fu-haptics/bind-aw86937"
  write_systemd_unit "$pkg/usr/lib/systemd/system/tb321fu-haptics.service"
  write_udev_rules "$pkg/usr/lib/udev/rules.d/90-tb321fu-haptics.rules"
  write_legacy_module_blacklist "$pkg/etc/modprobe.d/tb321fu-haptics.conf"
  write_plasma_keyboard_default "$pkg/etc/skel/.config/plasmakeyboardrc"

  haptics_run_isolated_tool aarch64-linux-gnu-gcc \
    -O2 -Wall -Wextra -o "$pkg/usr/bin/tb321fu-haptic-test" "$helper_src"
  verify_private_haptics_source_snapshot "after package input consumption"
  chmod 0755 "$pkg/usr/bin/tb321fu-haptic-test"
  strip_if_requested "$pkg/usr/bin/tb321fu-haptic-test"

  strip_if_requested "$pkg/usr/lib/modules/$kernel_release/extra/aw86937-haptics.ko"
  haptics_module_sha256=$(haptics_sha256_file \
    "$pkg/usr/lib/modules/$kernel_release/extra/aw86937-haptics.ko")
  haptics_test_helper_binary_sha256=$(haptics_sha256_file \
    "$pkg/usr/bin/tb321fu-haptic-test")
  write_control "$pkg"
  haptics_write_maintainer_scripts "$pkg" "$kernel_release"

  find "$pkg" -type d -exec chmod 0755 {} +
  find "$pkg" -xdev -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  haptics_deb_name="tb321fu-haptics_${HAPTICS_DEB_VERSION}_${ARCH}.deb"
  deb="$OUTPUT_DIR/$haptics_deb_name"
  haptics_run_isolated_tool dpkg-deb \
    --build --root-owner-group --uniform-compression --threads-max=1 \
    -Zxz -z6 "$pkg" "$deb" >/dev/null
  verify_built_haptics_deb "$pkg" "$deb"
  "${HAPTICS_BUILD_TOOL_PATHS[sha256sum]}" "$deb"
}

verify_built_haptics_deb() {
  haptics_run_isolated_tool bash "$SCRIPT_DIR/verify-haptics-deb.sh" \
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

  [ "$(haptics_sha256_file "$source_root/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c")" = "$haptics_driver_source_sha256" ] ||
    ci_die "staged AW86937 driver snapshot changed"
  [ "$(haptics_sha256_file "$stage/build/aw86937-haptics.c")" = "$haptics_build_source_sha256" ] ||
    ci_die "staged AW86937 build source changed"
  [ "$(haptics_sha256_file "$source_root/haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin")" = "$haptics_ram_firmware_sha256" ] ||
    ci_die "staged haptic_ram.bin changed"
  [ "$(haptics_sha256_file "$source_root/haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin")" = "$haptics_click_firmware_sha256" ] ||
    ci_die "staged haptic_click.bin changed"
  [ "$(haptics_sha256_file "$source_root/haptics/baseline-20260614-daily-clean/testing-tools/y700-haptic-test.c")" = "$haptics_test_helper_sha256" ] ||
    ci_die "staged haptics test helper source changed"
}

write_haptics_source_lock() {
  {
    printf 'schema\t%s\n' "$haptics_source_lock_schema"
    printf 'haptics-output-mode\t%s\n' "$haptics_output_mode"
    printf 'haptics-producer-commit\t%s\n' "$haptics_producer_commit"
    printf 'haptics-producer-state\t%s\n' "$haptics_producer_state"
    printf 'environment-policy\t%s\n' "$HAPTICS_BUILD_ENVIRONMENT_POLICY"
    printf 'environment-policy-sha256\t%s\n' "$HAPTICS_BUILD_ENVIRONMENT_POLICY_SHA256"
    printf 'build-toolset-sha256\t%s\n' "$HAPTICS_BUILD_TOOLSET_SHA256"
    printf 'build-tools-manifest\t%s\n' HAPTICS-BUILD-TOOLS.tsv
    printf 'build-tools-manifest-sha256\t%s\n' "$build_tools_manifest_sha256"
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
    printf 'kernel-build-input\t%s\n' "$kernel_build_input"
    printf 'kernel-build-archive-sha256\t%s\n' "$kernel_build_archive_identity"
    printf 'source-date-epoch\t%s\n' "$SOURCE_DATE_EPOCH"
  } > "$OUTPUT_DIR/HAPTICS-SOURCE-LOCK.tsv"
}

write_haptics_checksums() {
  (
    cd "$OUTPUT_DIR"
    "${HAPTICS_BUILD_TOOL_PATHS[sha256sum]}" \
      "./$haptics_deb_name" \
      ./HAPTICS-SOURCE-LOCK.tsv \
      ./HAPTICS-BUILD-TOOLS.tsv \
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
    HAPTICS-BUILD-TOOLS.tsv
    HAPTICS-PRODUCER.bundle
    HAPTICS-SOURCE-LOCK.tsv
    HAPTICS-SOURCE-SNAPSHOT
    SHA256SUMS-tb321fu-haptics-debs.txt
    "$haptics_deb_name"
  )
  local -a actual_root=() expected_manifest=(
    "./$haptics_deb_name"
    ./HAPTICS-SOURCE-LOCK.tsv
    ./HAPTICS-BUILD-TOOLS.tsv
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
    HAPTICS-BUILD-TOOLS.tsv \
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
  (cd "$OUTPUT_DIR" && \
    "${HAPTICS_BUILD_TOOL_PATHS[sha256sum]}" --strict \
      -c SHA256SUMS-tb321fu-haptics-debs.txt >/dev/null)

  [ ! -e "$output_path" ] || ci_die "OUTPUT_DIR appeared during atomic promotion: $output_path"
  haptics_verify_build_tools_unchanged "after external-module and DEB production"
  chmod 0755 "$OUTPUT_DIR"
  mv -T -- "$OUTPUT_DIR" "$output_path"
  output_stage=
  OUTPUT_DIR=$output_path
}

prepare_inputs
verify_haptics_producer_state "before package build"
validate_haptics_maintainer_source_contract
prepare_haptics_source_snapshot
create_haptics_producer_bundle
prepare_kernel_host_tools
build_haptics_package
verify_kernel_source_state "after package build"
verify_haptics_producer_state "after package build"
verify_private_haptics_source_snapshot "before final source snapshot staging"
stage_haptics_source_snapshot
install -m 0644 "$producer_bundle" "$OUTPUT_DIR/HAPTICS-PRODUCER.bundle"
haptics_verify_build_tools_unchanged "before build-environment evidence"
haptics_write_build_tools_manifest "$OUTPUT_DIR/HAPTICS-BUILD-TOOLS.tsv"
haptics_verify_build_tools_manifest "$OUTPUT_DIR/HAPTICS-BUILD-TOOLS.tsv"
build_tools_manifest_sha256=$(haptics_sha256_file "$OUTPUT_DIR/HAPTICS-BUILD-TOOLS.tsv")
write_haptics_source_lock

ci_log "writing haptics package checksums"
write_haptics_checksums
finalize_haptics_output
ci_log "haptics package build complete: $OUTPUT_DIR"
