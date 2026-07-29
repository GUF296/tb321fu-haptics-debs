#!/bin/sh
if [ "${HAPTICS_WRAPPER_CLEAN_ENV:-}" != 1 ] || [ -z "${BASH_VERSION:-}" ]; then
  script_path=$(/usr/bin/realpath -e -- "$0") || exit 1
  exec /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C LC_ALL=C TZ=UTC HOME=/nonexistent TMPDIR=/tmp \
    HAPTICS_WRAPPER_CLEAN_ENV=1 \
    OUTPUT_DIR="${OUTPUT_DIR-}" \
    ARCH="${ARCH-}" \
    HAPTICS_DEB_VERSION="${HAPTICS_DEB_VERSION-}" \
    HAPTICS_STRIP="${HAPTICS_STRIP-}" \
    HAPTICS_RELEASE_MODE="${HAPTICS_RELEASE_MODE-}" \
    HAPTICS_PRODUCER_COMMIT="${HAPTICS_PRODUCER_COMMIT-}" \
    KERNEL_SOURCE_REPO="${KERNEL_SOURCE_REPO-}" \
    KERNEL_SOURCE_COMMIT="${KERNEL_SOURCE_COMMIT-}" \
    KERNEL_BUILD_ARCHIVE="${KERNEL_BUILD_ARCHIVE-}" \
    KERNEL_BUILD_ARCHIVE_SHA256="${KERNEL_BUILD_ARCHIVE_SHA256-}" \
    KERNEL_BUNDLE_METADATA="${KERNEL_BUNDLE_METADATA-}" \
    KERNEL_BUNDLE_METADATA_SHA256="${KERNEL_BUNDLE_METADATA_SHA256-}" \
    KERNEL_SDK_MANIFEST="${KERNEL_SDK_MANIFEST-}" \
    SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH-}" \
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
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)
. "$SCRIPT_DIR/common.sh"
. "$SCRIPT_DIR/haptics-build-environment.sh"
. "$SCRIPT_DIR/haptics-kernel-sdk-contract.sh"

haptics_enter_clean_environment HAPTICS_WRAPPER_CLEAN_ENV "$SCRIPT_PATH" \
  OUTPUT_DIR \
  ARCH \
  HAPTICS_DEB_VERSION \
  HAPTICS_STRIP \
  HAPTICS_RELEASE_MODE \
  HAPTICS_PRODUCER_COMMIT \
  KERNEL_SOURCE_REPO \
  KERNEL_SOURCE_COMMIT \
  KERNEL_BUILD_ARCHIVE \
  KERNEL_BUILD_ARCHIVE_SHA256 \
  KERNEL_BUNDLE_METADATA \
  KERNEL_BUNDLE_METADATA_SHA256 \
  KERNEL_SDK_MANIFEST \
  SOURCE_DATE_EPOCH \
  -- "$@"

set -euo pipefail
umask 022

OUTPUT_DIR=${OUTPUT_DIR:-out/tb321fu-haptics-debs}
ARCH=${ARCH:-arm64}
HAPTICS_DEB_VERSION=${HAPTICS_DEB_VERSION:-20260627.1}
HAPTICS_STRIP=${HAPTICS_STRIP:-1}
HAPTICS_RELEASE_MODE=${HAPTICS_RELEASE_MODE:-}
HAPTICS_PRODUCER_COMMIT=${HAPTICS_PRODUCER_COMMIT:-}
KERNEL_SOURCE_REPO=${KERNEL_SOURCE_REPO:-https://github.com/GUF296/linux.git}
KERNEL_SOURCE_COMMIT=${KERNEL_SOURCE_COMMIT:-5df8e852ea722929f5359a5ef28ebcec0c4443fd}
KERNEL_BUILD_ARCHIVE=${KERNEL_BUILD_ARCHIVE:-https://github.com/GUF296/tb321fu-haptics-debs/releases/download/kernel-sdk-7.1.1-g5df8e852ea72/tb321fu-kernel-build-sdk-7.1.1-g5df8e852ea72.tar.gz}
KERNEL_BUILD_ARCHIVE_SHA256=${KERNEL_BUILD_ARCHIVE_SHA256:-75703c4cf2ed10777905d79c57103ce1a9e50a02d09507c4aa15eb81b27c845a}
KERNEL_BUNDLE_METADATA=${KERNEL_BUNDLE_METADATA:-}
KERNEL_BUNDLE_METADATA_SHA256=${KERNEL_BUNDLE_METADATA_SHA256:-}
KERNEL_SDK_MANIFEST=${KERNEL_SDK_MANIFEST:-}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}

[[ $HAPTICS_PRODUCER_COMMIT =~ ^[0-9a-f]{40}$ ]] || ci_die "invalid HAPTICS_PRODUCER_COMMIT"
[[ $KERNEL_SOURCE_COMMIT =~ ^[0-9a-f]{40}$ ]] || ci_die "invalid KERNEL_SOURCE_COMMIT"
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]{1,10}$ ]] || ci_die "invalid SOURCE_DATE_EPOCH"
[ "$HAPTICS_RELEASE_MODE" = 1 ] ||
  ci_die "kernel SDK archive packaging requires HAPTICS_RELEASE_MODE=1"
haptics_validate_kernel_build_input_contract \
  "$HAPTICS_RELEASE_MODE" \
  "$KERNEL_BUILD_ARCHIVE" \
  "$KERNEL_BUILD_ARCHIVE_SHA256" \
  "" \
  "$KERNEL_BUNDLE_METADATA" \
  "$KERNEL_BUNDLE_METADATA_SHA256" \
  "$KERNEL_SDK_MANIFEST"

output_requested=$(ci_abs_path "$OUTPUT_DIR")
output_parent=$(dirname -- "$output_requested")
output_name=$(basename -- "$output_requested")
[[ $output_name =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] ||
  ci_die "unsafe OUTPUT_DIR basename: $output_name"
mkdir -p "$output_parent"
output_parent=$(realpath -e -- "$output_parent")
output_path="$output_parent/$output_name"
[ ! -e "$output_path" ] || ci_die "refusing stale OUTPUT_DIR: $output_path"

haptics_capture_build_tools
haptics_verify_expected_build_environment
preflight_haptics_commit=$(ci_verify_clean_git_commit "$REPO_ROOT" "$HAPTICS_PRODUCER_COMMIT")
[ "$preflight_haptics_commit" = "$HAPTICS_PRODUCER_COMMIT" ] ||
  ci_die "haptics producer preflight returned an unexpected commit"
ci_log "haptics producer preflight passed: $preflight_haptics_commit"

delivery_stage=
producer_output=
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/tb321fu-haptics-kernel.XXXXXX")
cleanup() {
  rm -rf -- "$work_dir"
  if [ -n "$delivery_stage" ] && [ -d "$delivery_stage" ]; then
    chmod -R u+w "$delivery_stage" 2>/dev/null || true
    rm -rf -- "$delivery_stage"
  fi
}
trap cleanup EXIT

delivery_stage=$(mktemp -d "$output_parent/.${output_name}.delivery.XXXXXX")
chmod 0700 "$delivery_stage"
producer_output="$delivery_stage/producer-output"

kernel_source="$work_dir/linux"
ci_log "fetching exact kernel source: $KERNEL_SOURCE_REPO $KERNEL_SOURCE_COMMIT"
ci_git init -q "$kernel_source"
ci_git -C "$kernel_source" remote add origin "$KERNEL_SOURCE_REPO"
ci_git -C "$kernel_source" fetch --depth 1 origin "$KERNEL_SOURCE_COMMIT"
ci_git -C "$kernel_source" checkout -q --detach FETCH_HEAD
actual_kernel_commit=$(ci_git -C "$kernel_source" rev-parse HEAD)
[ "$actual_kernel_commit" = "$KERNEL_SOURCE_COMMIT" ] ||
  ci_die "kernel fetch returned $actual_kernel_commit instead of $KERNEL_SOURCE_COMMIT"

producer_env=(
  "PATH=$HAPTICS_BUILD_PATH"
  LANG=C
  LC_ALL=C
  TZ=UTC
  "HOME=$HAPTICS_BUILD_HOME"
  "TMPDIR=$HAPTICS_BUILD_TMPDIR"
  HAPTICS_BUILDER_CLEAN_ENV=1
  OUTPUT_DIR="$producer_output"
  ARCH="$ARCH"
  HAPTICS_DEB_VERSION="$HAPTICS_DEB_VERSION"
  HAPTICS_SOURCE_DIR="$REPO_ROOT"
  EXPECTED_HAPTICS_PRODUCER_COMMIT="$HAPTICS_PRODUCER_COMMIT"
  HAPTICS_RELEASE_MODE="$HAPTICS_RELEASE_MODE"
  KERNEL_SOURCE_DIR="$kernel_source"
  KERNEL_BUILD_ARCHIVE="$KERNEL_BUILD_ARCHIVE"
  KERNEL_BUILD_ARCHIVE_SHA256="$KERNEL_BUILD_ARCHIVE_SHA256"
  KERNEL_BUNDLE_METADATA="$KERNEL_BUNDLE_METADATA"
  KERNEL_BUNDLE_METADATA_SHA256="$KERNEL_BUNDLE_METADATA_SHA256"
  KERNEL_SDK_MANIFEST="$KERNEL_SDK_MANIFEST"
  EXPECTED_KERNEL_SOURCE_COMMIT="$KERNEL_SOURCE_COMMIT"
  HAPTICS_STRIP="$HAPTICS_STRIP"
  SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH"
  EXPECTED_HAPTICS_BUILD_TOOLSET_SHA256="$HAPTICS_BUILD_TOOLSET_SHA256"
  EXPECTED_HAPTICS_BUILD_ENVIRONMENT_POLICY_SHA256="$HAPTICS_BUILD_ENVIRONMENT_POLICY_SHA256"
)
producer_env+=("${HAPTICS_TRANSPORT_ENVIRONMENT[@]}")
"${HAPTICS_BUILD_TOOL_PATHS[env]}" -i "${producer_env[@]}" \
  "${HAPTICS_BUILD_TOOL_PATHS[bash]}" "$SCRIPT_DIR/build-tb321fu-haptics-deb.sh"

deb_name="tb321fu-haptics_${HAPTICS_DEB_VERSION}_${ARCH}.deb"
archive_name="tb321fu-haptics-debs_${HAPTICS_DEB_VERSION}_${ARCH}.tar.gz"
archive_tmp="$producer_output/.${archive_name}.part"
archive_manifest=SHA256SUMS-archive.txt
compiled_digests=HAPTICS-COMPILED-DIGESTS.env
archive_members=(
  "$deb_name"
  HAPTICS-SOURCE-LOCK.tsv
  HAPTICS-BUILD-TOOLS.tsv
  HAPTICS-PRODUCER.bundle
  HAPTICS-SOURCE-SNAPSHOT/source/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c
  HAPTICS-SOURCE-SNAPSHOT/build/aw86937-haptics.c
  HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin
  HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin
  HAPTICS-SOURCE-SNAPSHOT/source/haptics/baseline-20260614-daily-clean/testing-tools/y700-haptic-test.c
  SHA256SUMS-tb321fu-haptics-debs.txt
)

for member in "${archive_members[@]}"; do
  [ -f "$producer_output/$member" ] && [ ! -L "$producer_output/$member" ] ||
    ci_die "missing exact haptics archive member: $member"
done
(
  cd "$producer_output"
  haptics_run_isolated_tool tar --format=gnu --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
    -cf - -- "${archive_members[@]}"
) | haptics_run_isolated_tool gzip -n > "$archive_tmp"
chmod 0644 "$archive_tmp"

archive_member_list="$work_dir/haptics-archive-members.list"
haptics_run_isolated_tool tar -tzf "$archive_tmp" > "$archive_member_list" ||
  ci_die "cannot completely list the generated haptics archive"
[ "$(stat -c '%s' "$archive_member_list")" -le 65536 ] ||
  ci_die "generated haptics archive member listing exceeds its size bound"
mapfile -t actual_archive_members < "$archive_member_list"
[ "${#actual_archive_members[@]}" -eq "${#archive_members[@]}" ] ||
  ci_die "haptics archive has an unexpected member count"
for index in "${!archive_members[@]}"; do
  [ "${actual_archive_members[$index]}" = "${archive_members[$index]}" ] ||
    ci_die "haptics archive member mismatch: expected ${archive_members[$index]}, got ${actual_archive_members[$index]}"
done
mapfile -t archive_roots < <(printf '%s\n' "${actual_archive_members[@]}" | cut -d/ -f1 | sort -u)
expected_archive_roots=(
  HAPTICS-BUILD-TOOLS.tsv
  HAPTICS-PRODUCER.bundle
  HAPTICS-SOURCE-LOCK.tsv
  HAPTICS-SOURCE-SNAPSHOT
  SHA256SUMS-tb321fu-haptics-debs.txt
  "$deb_name"
)
[ "${#archive_roots[@]}" -eq "${#expected_archive_roots[@]}" ] ||
  ci_die "haptics archive has an unexpected root entry count"
for index in "${!expected_archive_roots[@]}"; do
  [ "${archive_roots[$index]}" = "${expected_archive_roots[$index]}" ] ||
    ci_die "haptics archive root mismatch: expected ${expected_archive_roots[$index]}, got ${archive_roots[$index]}"
done

mv -- "$archive_tmp" "$producer_output/$archive_name"
(
  cd "$producer_output"
  "${HAPTICS_BUILD_TOOL_PATHS[sha256sum]}" "./$archive_name" > "$archive_manifest"
)

lock_value() {
  local key=$1 value count
  count=$(awk -F '\t' -v key="$key" '$1 == key { count++ } END { print count + 0 }' \
    "$producer_output/HAPTICS-SOURCE-LOCK.tsv")
  [ "$count" -eq 1 ] || ci_die "source lock must contain exactly one $key"
  value=$(awk -F '\t' -v key="$key" '$1 == key { print $2 }' \
    "$producer_output/HAPTICS-SOURCE-LOCK.tsv")
  printf '%s\n' "$value"
}

source_lock_schema=$(lock_value schema)
source_lock_mode=$(lock_value haptics-output-mode)
source_lock_input=$(lock_value kernel-build-input)
source_lock_archive_sha256=$(lock_value kernel-build-archive-sha256)
source_lock_bundle_id=$(lock_value kernel-bundle-id)
source_lock_environment_policy=$(lock_value environment-policy)
source_lock_environment_policy_sha256=$(lock_value environment-policy-sha256)
source_lock_toolset_sha256=$(lock_value build-toolset-sha256)
source_lock_tools_manifest=$(lock_value build-tools-manifest)
source_lock_tools_manifest_sha256=$(lock_value build-tools-manifest-sha256)
[ "$source_lock_schema" = tb321fu.haptics-source-lock/v3 ] ||
  ci_die "release haptics source lock has an unsupported schema: $source_lock_schema"
[ "$source_lock_mode" = release-candidate ] ||
  ci_die "release haptics source lock is not a release candidate: $source_lock_mode"
[ "$source_lock_input" = kernel-sdk-archive ] ||
  ci_die "release haptics source lock does not identify a kernel SDK archive"
[ "$source_lock_archive_sha256" = "${KERNEL_BUILD_ARCHIVE_SHA256,,}" ] ||
  ci_die "release haptics source lock does not bind the requested kernel SDK archive"
[[ $source_lock_bundle_id =~ ^[0-9a-f]{64}$ ]] ||
  ci_die "release haptics source lock has an invalid kernel bundle identity"
[ "$source_lock_environment_policy" = "$HAPTICS_BUILD_ENVIRONMENT_POLICY" ] ||
  ci_die "release haptics source lock has an unexpected environment policy"
[ "$source_lock_environment_policy_sha256" = "$HAPTICS_BUILD_ENVIRONMENT_POLICY_SHA256" ] ||
  ci_die "release haptics source lock does not bind the wrapper environment policy"
[ "$source_lock_toolset_sha256" = "$HAPTICS_BUILD_TOOLSET_SHA256" ] ||
  ci_die "release haptics source lock does not bind the wrapper build tools"
[ "$source_lock_tools_manifest" = HAPTICS-BUILD-TOOLS.tsv ] ||
  ci_die "release haptics source lock names an unexpected build-tools manifest"
haptics_verify_build_tools_manifest "$producer_output/HAPTICS-BUILD-TOOLS.tsv"
[ "$source_lock_tools_manifest_sha256" = \
  "$(haptics_sha256_file "$producer_output/HAPTICS-BUILD-TOOLS.tsv")" ] ||
  ci_die "release haptics source lock does not bind HAPTICS-BUILD-TOOLS.tsv"

module_sha256=$(lock_value aw86937-module-sha256)
helper_sha256=$(lock_value haptic-test-helper-binary-sha256)
[[ $module_sha256 =~ ^[0-9a-f]{64}$ ]] || ci_die "invalid module digest in source lock"
[[ $helper_sha256 =~ ^[0-9a-f]{64}$ ]] || ci_die "invalid helper digest in source lock"
deb_sha256=$(haptics_sha256_file "$producer_output/$deb_name")
archive_sha256=$(haptics_sha256_file "$producer_output/$archive_name")
printf '%s\n' \
  "HAPTICS_PRODUCER_COMMIT=$HAPTICS_PRODUCER_COMMIT" \
  "HAPTICS_DEB_SHA256=$deb_sha256" \
  "HAPTICS_ARCHIVE_SHA256=$archive_sha256" \
  "HAPTICS_MODULE_SHA256=$module_sha256" \
  "HAPTICS_HELPER_BINARY_SHA256=$helper_sha256" \
  > "$producer_output/$compiled_digests"
chmod 0644 "$producer_output/$compiled_digests"

expected_output_roots=(
  HAPTICS-BUILD-TOOLS.tsv
  HAPTICS-COMPILED-DIGESTS.env
  HAPTICS-PRODUCER.bundle
  HAPTICS-SOURCE-LOCK.tsv
  HAPTICS-SOURCE-SNAPSHOT
  SHA256SUMS-archive.txt
  SHA256SUMS-tb321fu-haptics-debs.txt
  "$archive_name"
  "$deb_name"
)
mapfile -t actual_output_roots < <(find "$producer_output" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
[ "${#actual_output_roots[@]}" -eq "${#expected_output_roots[@]}" ] ||
  ci_die "haptics delivery staging has an unexpected root entry count"
for index in "${!expected_output_roots[@]}"; do
  [ "${actual_output_roots[$index]}" = "${expected_output_roots[$index]}" ] ||
    ci_die "haptics delivery root mismatch: expected ${expected_output_roots[$index]}, got ${actual_output_roots[$index]}"
done
(cd "$producer_output" && \
  "${HAPTICS_BUILD_TOOL_PATHS[sha256sum]}" --strict -c "$archive_manifest" >/dev/null)

[ ! -e "$output_path" ] && [ ! -L "$output_path" ] ||
  ci_die "OUTPUT_DIR appeared during atomic promotion: $output_path"
haptics_verify_build_tools_unchanged "after wrapper archive packaging"
haptics_promote_directory_no_clobber "$producer_output" "$output_path"
producer_output=
ci_log "haptics deb archive ready: $output_path/$archive_name"
ci_log "compiled digest evidence ready: $output_path/$compiled_digests"
