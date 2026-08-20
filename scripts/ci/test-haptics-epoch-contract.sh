#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)
. "$SCRIPT_DIR/common.sh"
. "$SCRIPT_DIR/haptics-build-environment.sh"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/tb321fu-haptics-epoch.XXXXXX")
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
  [ "$status" -ne 0 ] || fail "hostile epoch fixture unexpectedly passed"
  grep -Fq -- "$expected" <<<"$output" ||
    fail "hostile epoch fixture failed at the wrong boundary: $output"
}

for epoch in 1234567890 12345678901 15032385535; do
  haptics_epoch_is_valid "$epoch" || fail "valid epoch was rejected: $epoch"
  haptics_epoch_roundtrips "$epoch" ||
    fail "valid epoch did not round-trip through the build filesystem: $epoch"
  SOURCE_DATE_EPOCH=$epoch
  haptics_validate_clean_input SOURCE_DATE_EPOCH
done
for epoch in '' -1 15032385536 999999999999 1000000000000; do
  if haptics_epoch_is_valid "$epoch"; then
    fail "invalid epoch was accepted: ${epoch:-<empty>}"
  fi
done
if haptics_epoch_roundtrips 999999999999; then
  fail "unrepresentable 12-digit epoch passed the filesystem round-trip gate"
fi
SOURCE_DATE_EPOCH=999999999999
require_failure 'invalid SOURCE_DATE_EPOCH' \
  haptics_validate_clean_input SOURCE_DATE_EPOCH

HAPTICS_BUILD_TOOL_COMMAND_PATHS[env]=/usr/bin/env
HAPTICS_BUILD_TOOL_COMMAND_PATHS[printf]=/usr/bin/printf
for epoch in 1234567890 12345678901 15032385535; do
  SOURCE_DATE_EPOCH=$epoch
  actual=$(haptics_run_isolated_tool printf '%s' "$SOURCE_DATE_EPOCH")
  [ "$actual" = "$epoch" ] || fail "isolated tool lost a valid epoch: $epoch"
done
SOURCE_DATE_EPOCH=999999999999
require_failure 'invalid SOURCE_DATE_EPOCH for isolated tool' \
  haptics_run_isolated_tool printf '%s' "$SOURCE_DATE_EPOCH"

extract_function() {
  local name=$1 source=$2 destination=$3

  awk -v signature="${name}() {" '
    index($0, signature) == 1 { emit = 1 }
    emit { print }
    emit && /^}$/ { exit }
  ' "$source" > "$destination"
  [ -s "$destination" ] || fail "could not extract function: $name"
}

builder="$SCRIPT_DIR/build-tb321fu-haptics-deb.sh"
extract_function load_kernel_bundle_metadata "$builder" "$tmp/load-kernel-bundle.sh"
extract_function verify_haptics_producer_state "$builder" "$tmp/verify-producer.sh"
extract_function write_haptics_source_lock "$builder" "$tmp/write-source-lock.sh"
. "$tmp/load-kernel-bundle.sh"
. "$tmp/verify-producer.sh"
. "$tmp/write-source-lock.sh"

kernel_epoch=1784752597
producer_epoch=1785426471
kernel_metadata="$tmp/KERNEL-BUNDLE.fixture.tsv"
{
  printf 'kernel-source-commit\t%s\n' "$(printf '1%.0s' {1..40})"
  printf 'kernel-release\t%s\n' 7.1.1-00009-g111111111111
  printf 'kernel-config-sha256\t%s\n' "$(printf '2%.0s' {1..64})"
  printf 'kernel-sdk-archive-sha256\t%s\n' "$(printf '3%.0s' {1..64})"
  printf 'kernel-sdk-manifest-sha256\t%s\n' "$(printf '4%.0s' {1..64})"
  printf 'kernel-toolchain-manifest-sha256\t%s\n' "$(printf '5%.0s' {1..64})"
  printf 'source-date-epoch\t%s\n' "$kernel_epoch"
  printf 'kbuild-build-timestamp\t%s\n' '2026-07-22 20:36:37 UTC'
  printf 'kbuild-build-user\t%s\n' tb321fu-ci
  printf 'kbuild-build-host\t%s\n' tb321fu-builder
  printf 'kbuild-build-version\t%s\n' 1
  printf 'kernel-bundle-id\t%s\n' "$(printf '6%.0s' {1..64})"
} > "$kernel_metadata"
(
  work_dir="$tmp/kernel-metadata-work"
  mkdir -p "$work_dir"
  KERNEL_BUNDLE_METADATA=https://example.invalid/KERNEL-BUNDLE.tsv
  KERNEL_BUNDLE_METADATA_SHA256=$(printf '7%.0s' {1..64})
  EXPECTED_KERNEL_SOURCE_COMMIT=$(printf '1%.0s' {1..40})
  SOURCE_DATE_EPOCH=$producer_epoch
  ci_download() { cp -- "$kernel_metadata" "$2"; }
  haptics_run_isolated_tool() { cat -- "$kernel_metadata"; }
  load_kernel_bundle_metadata
  printf '%s\n' "$SOURCE_DATE_EPOCH" > "$tmp/loaded-kernel-epoch"
)
[ "$(cat "$tmp/loaded-kernel-epoch")" = "$kernel_epoch" ] ||
  fail "kernel bundle epoch did not become the reproducible build epoch"

producer_repo="$tmp/producer"
git init -q "$producer_repo"
git -C "$producer_repo" config user.name fixture
git -C "$producer_repo" config user.email fixture@example.invalid
printf 'fixture\n' > "$producer_repo/source"
git -C "$producer_repo" add source
GIT_AUTHOR_DATE="@$producer_epoch +0000" \
GIT_COMMITTER_DATE="@$producer_epoch +0000" \
  git -C "$producer_repo" commit -q -m fixture
producer_commit=$(git -C "$producer_repo" rev-parse HEAD)

haptics_root=$producer_repo
EXPECTED_HAPTICS_PRODUCER_COMMIT=$producer_commit
HAPTICS_GIT_DIR=
haptics_producer_commit=
haptics_producer_state=
haptics_producer_epoch=
verify_haptics_producer_state 'in epoch fixture'
[ "$haptics_producer_epoch" = "$producer_epoch" ] ||
  fail "producer state did not derive the exact Git commit epoch"

OUTPUT_DIR="$tmp/output"
mkdir -p "$OUTPUT_DIR"
haptics_source_lock_schema=tb321fu.haptics-source-lock/v4
haptics_output_mode=release-candidate
HAPTICS_BUILD_ENVIRONMENT_POLICY=fixture-policy
HAPTICS_BUILD_ENVIRONMENT_POLICY_SHA256=$(printf '8%.0s' {1..64})
HAPTICS_BUILD_TOOLSET_SHA256=$(printf '9%.0s' {1..64})
build_tools_manifest_sha256=$(printf 'a%.0s' {1..64})
haptics_driver_source_sha256=$(printf 'b%.0s' {1..64})
haptics_build_source_sha256=$(printf 'c%.0s' {1..64})
haptics_ram_firmware_sha256=$(printf 'd%.0s' {1..64})
haptics_click_firmware_sha256=$(printf 'e%.0s' {1..64})
haptics_test_helper_sha256=$(printf 'f%.0s' {1..64})
haptics_module_sha256=$(printf '0%.0s' {1..64})
haptics_test_helper_binary_sha256=$(printf '1%.0s' {1..64})
kernel_bundle_id=$(printf '2%.0s' {1..64})
kernel_bundle_toolchain_manifest_sha256=$(printf '3%.0s' {1..64})
kernel_release=7.1.1-00009-g111111111111
EXPECTED_KERNEL_SOURCE_COMMIT=$(printf '4%.0s' {1..40})
kernel_bundle_config_sha256=$(printf '5%.0s' {1..64})
kernel_build_input=kernel-sdk-archive
kernel_build_archive_identity=$(printf '6%.0s' {1..64})
SOURCE_DATE_EPOCH=$kernel_epoch
write_haptics_source_lock

lock_epoch=$(awk -F '\t' '$1 == "source-date-epoch" { print $2 }' \
  "$OUTPUT_DIR/HAPTICS-SOURCE-LOCK.tsv")
[ "$lock_epoch" = "$producer_epoch" ] ||
  fail "source lock did not record the producer Git epoch"
[ "$lock_epoch" != "$SOURCE_DATE_EPOCH" ] ||
  fail "source lock conflated the producer and kernel build epochs"
[ "$SOURCE_DATE_EPOCH" = "$kernel_epoch" ] ||
  fail "source-lock creation changed the kernel reproducibility epoch"

grep -Fq '[ "$source_lock_epoch" = "$haptics_producer_epoch" ]' \
  "$SCRIPT_DIR/build-tb321fu-haptics-deb-from-kernel-sdk.sh" ||
  fail "SDK wrapper does not verify the emitted producer epoch"
grep -Fq '[ "$SOURCE_DATE_EPOCH" = "$haptics_producer_epoch" ]' \
  "$SCRIPT_DIR/build-tb321fu-haptics-deb-from-kernel-sdk.sh" ||
  fail "SDK wrapper does not bind the outer archive epoch to the producer commit"

printf 'HAPTICS_EPOCH_CONTRACT=PASS\n'
