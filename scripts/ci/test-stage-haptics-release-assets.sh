#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)
. "$SCRIPT_DIR/common.sh"

[ "$#" -eq 1 ] || {
  printf 'usage: test-stage-haptics-release-assets.sh A12_OUTPUT_DIR\n' >&2
  exit 2
}
a12=$1
[ -d "$a12" ] && [ ! -L "$a12" ] || ci_die "A12 fixture is not a real directory"
a12=$(realpath -e -- "$a12")

tmp=$(mktemp -d "${TMPDIR:-/tmp}/tb321fu-stage-a12.XXXXXX")
cleanup() { rm -rf -- "$tmp"; }
trap cleanup EXIT

fail() {
  printf 'stage fixture failure: %s\n' "$*" >&2
  exit 1
}

reference="$SCRIPT_DIR/HAPTICS-RELEASE-REFERENCE.tsv"
/usr/bin/python3 -I "$SCRIPT_DIR/verify-haptics-release-reference.py" "$reference"
reference_value() {
  local key=$1 count

  count=$(awk -F '\t' -v key="$key" '$1 == key { count++ } END { print count + 0 }' "$reference")
  [ "$count" -eq 1 ] || fail "reference key is not unique: $key"
  awk -F '\t' -v key="$key" '$1 == key { print $2 }' "$reference"
}

version=$(reference_value package-version)
producer_commit=$(reference_value reference-producer-commit)
reference_archive_sha=$(reference_value reference-archive-sha256)
toolchain_sha=$(reference_value kernel-toolchain-manifest-sha256)
kernel_archive_url=$(reference_value kernel-build-archive-url)
kernel_archive_sha=$(reference_value kernel-build-archive-sha256)
kernel_metadata_url=$(reference_value kernel-bundle-metadata-url)
kernel_metadata_sha=$(reference_value kernel-bundle-metadata-sha256)
kernel_sdk_manifest_url=$(reference_value kernel-sdk-manifest-url)
kernel_toolchain_manifest_url=$(reference_value kernel-toolchain-manifest-url)
kernel_source_commit=$(reference_value kernel-source-commit)
producer_epoch=$(ci_git show -s --format=%ct "$producer_commit^{commit}")
[[ $producer_epoch =~ ^[0-9]{1,11}$ ]] && [ "$producer_epoch" -le 15032385535 ] ||
  fail "reference producer epoch is invalid"

producer="$tmp/producer"
mkdir -p "$producer"
cp -a --reflink=auto -- "$a12/." "$producer/"
archive="$producer/tb321fu-haptics-debs_${version}_arm64.tar.gz"
[ -f "$archive" ] && [ ! -L "$archive" ] || fail "A12 archive is missing"
[ "$(/usr/bin/sha256sum -- "$archive" | /usr/bin/awk '{ print $1 }')" = \
  "$reference_archive_sha" ] || fail "A12 archive differs from the trusted reference digest"
archive_root="$tmp/archive"
/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C TZ=UTC \
  HOME=/nonexistent /usr/bin/python3 -I "$SCRIPT_DIR/safe-extract-archive.py" \
  "$archive" "$archive_root" || fail "trusted A12 archive failed safe extraction"
kernel_epoch=$(awk -F '\t' '$1 == "source-date-epoch" { print $2 }' \
  "$producer/HAPTICS-SOURCE-LOCK.tsv")
[[ $kernel_epoch =~ ^[0-9]{1,11}$ ]] && [ "$kernel_epoch" -le 15032385535 ] ||
  fail "A12 kernel epoch is invalid"
[ "$kernel_epoch" != "$producer_epoch" ] || fail "A12 fixture does not expose the epoch split"

for lock in "$producer/HAPTICS-SOURCE-LOCK.tsv" "$archive_root/HAPTICS-SOURCE-LOCK.tsv"; do
  awk -F '\t' -v OFS='\t' -v producer_epoch="$producer_epoch" \
    -v toolchain_sha="$toolchain_sha" '
      $1 == "schema" { $2 = "tb321fu.haptics-source-lock/v4" }
      $1 == "source-date-epoch" { $2 = producer_epoch }
      { print }
      $1 == "kernel-bundle-id" {
        print "kernel-toolchain-manifest-sha256", toolchain_sha
      }
    ' "$lock" > "$lock.next"
  mv -T -- "$lock.next" "$lock"
  [ "$(awk -F '\t' '$1 == "source-date-epoch" { print $2 }' "$lock")" = "$producer_epoch" ] ||
    fail "could not adapt the private source-lock epoch"
  [ "$(awk -F '\t' '$1 == "kernel-toolchain-manifest-sha256" { print $2 }' "$lock")" = "$toolchain_sha" ] ||
    fail "could not add the private v4 toolchain binding"
done

(
  cd "$archive_root"
  sha256sum -- \
    "./tb321fu-haptics_${version}_arm64.deb" \
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
cp -- "$archive_root/SHA256SUMS-tb321fu-haptics-debs.txt" \
  "$producer/SHA256SUMS-tb321fu-haptics-debs.txt"

archive_tmp="$tmp/adapted.tar.gz"
(
  cd "$archive_root"
  tar --format=gnu --mtime="@$producer_epoch" --owner=0 --group=0 --numeric-owner \
    -cf - -- \
    "tb321fu-haptics_${version}_arm64.deb" \
    HAPTICS-SOURCE-LOCK.tsv \
    HAPTICS-BUILD-TOOLS.tsv \
    HAPTICS-PRODUCER.bundle \
    HAPTICS-SOURCE-SNAPSHOT/source/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c \
    HAPTICS-SOURCE-SNAPSHOT/build/aw86937-haptics.c \
    HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin \
    HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin \
    HAPTICS-SOURCE-SNAPSHOT/source/haptics/baseline-20260614-daily-clean/testing-tools/y700-haptic-test.c \
    SHA256SUMS-tb321fu-haptics-debs.txt
) | gzip -n > "$archive_tmp"
chmod 0644 "$archive_tmp"
mv -T -- "$archive_tmp" "$archive"
archive_sha=$(sha256sum -- "$archive" | awk '{ print $1 }')
sed -i "s/^HAPTICS_ARCHIVE_SHA256=.*/HAPTICS_ARCHIVE_SHA256=$archive_sha/" \
  "$producer/HAPTICS-COMPILED-DIGESTS.env"
printf '%s  ./%s\n' "$archive_sha" "${archive##*/}" > "$producer/SHA256SUMS-archive.txt"

stage_args=(
  "$version"
  "$kernel_source_commit"
  "$kernel_archive_url"
  "$kernel_archive_sha"
  "$kernel_metadata_url"
  "$kernel_metadata_sha"
  "$kernel_sdk_manifest_url"
  "$kernel_toolchain_manifest_url"
  "$producer_commit"
  1
)

cd "$REPO_ROOT"
stage="$tmp/stage"
poison_dir="$tmp/poison"
/usr/bin/mkdir -p -- "$poison_dir"
bash_env_marker="$tmp/bash-env-executed"
python_marker="$tmp/pythonpath-executed"
function_marker="$tmp/exported-function-executed"
cat > "$poison_dir/bash-env.sh" <<'EOF_BASH_ENV'
[ -z "${HAPTICS_BASH_ENV_MARKER:-}" ] || : > "$HAPTICS_BASH_ENV_MARKER"
EOF_BASH_ENV
cat > "$poison_dir/sitecustomize.py" <<'EOF_SITECUSTOMIZE'
import os
import pathlib

marker = os.environ.get("HAPTICS_PYTHON_MARKER")
if marker:
    pathlib.Path(marker).touch()
EOF_SITECUSTOMIZE
HAPTICS_BASH_ENV_MARKER="$bash_env_marker" BASH_ENV="$poison_dir/bash-env.sh" \
  /bin/bash -c ':'
[ -e "$bash_env_marker" ] || fail "BASH_ENV hostile control did not execute"
/usr/bin/rm -f -- "$bash_env_marker"
HAPTICS_PYTHON_MARKER="$python_marker" PYTHONPATH="$poison_dir" \
  /usr/bin/python3 -c 'pass'
[ -e "$python_marker" ] || fail "PYTHONPATH hostile control did not execute"
/usr/bin/rm -f -- "$python_marker"
(
  dirname() { : > "$HAPTICS_FUNCTION_MARKER"; return 97; }
  export -f dirname
  HAPTICS_FUNCTION_MARKER="$function_marker" /bin/bash -c 'dirname >/dev/null 2>&1 || :'
)
[ -e "$function_marker" ] || fail "exported-function hostile control did not execute"
/usr/bin/rm -f -- "$function_marker"
(
  dirname() { : > "$HAPTICS_FUNCTION_MARKER"; return 97; }
  python3() { : > "$HAPTICS_FUNCTION_MARKER"; return 97; }
  export -f dirname python3
  HAPTICS_BASH_ENV_MARKER="$bash_env_marker" \
  HAPTICS_PYTHON_MARKER="$python_marker" \
  HAPTICS_FUNCTION_MARKER="$function_marker" \
  BASH_ENV="$poison_dir/bash-env.sh" PYTHONPATH="$poison_dir" \
    /bin/bash -p "$SCRIPT_DIR/stage-haptics-release-assets.sh" \
      "$producer" "$stage" "${stage_args[@]}"
)
[ ! -e "$bash_env_marker" ] || fail "stage executed hostile BASH_ENV"
[ ! -e "$python_marker" ] || fail "stage imported hostile PYTHONPATH"
[ ! -e "$function_marker" ] || fail "stage imported a hostile Bash function"
[ -d "$stage/assets" ] && [ ! -L "$stage/assets" ] || fail "successful stage is missing"
expected_stage_names=(
  BUILD-PARAMETERS.md
  HAPTICS-SOURCE-LOCK.tsv
  SHA256SUMS-tb321fu-haptics-debs.txt
  SHA256SUMS.txt
  "tb321fu-haptics-debs_${version}_arm64.tar.gz"
)
mapfile -t actual_stage_names < <(
  /usr/bin/find "$stage/assets" -mindepth 1 -maxdepth 1 -printf '%f\n' | /usr/bin/sort
)
[ "${#actual_stage_names[@]}" -eq "${#expected_stage_names[@]}" ] ||
  fail "successful stage does not contain exactly five entries"
for index in "${!expected_stage_names[@]}"; do
  [ "${actual_stage_names[$index]}" = "${expected_stage_names[$index]}" ] ||
    fail "successful stage has an unexpected asset: ${actual_stage_names[$index]}"
  [ "$(/usr/bin/stat -c '%a' -- "$stage/assets/${actual_stage_names[$index]}")" = 644 ] ||
    fail "successful stage asset is not mode 0644: ${actual_stage_names[$index]}"
done
expected_checksum_names=(
  "tb321fu-haptics-debs_${version}_arm64.tar.gz"
  HAPTICS-SOURCE-LOCK.tsv
  SHA256SUMS-tb321fu-haptics-debs.txt
  BUILD-PARAMETERS.md
)
mapfile -t actual_checksum_names < <(
  /usr/bin/awk '{ print $2 }' "$stage/assets/SHA256SUMS.txt"
)
[ "${#actual_checksum_names[@]}" -eq "${#expected_checksum_names[@]}" ] ||
  fail "outer checksum manifest does not contain exactly four records"
for index in "${!expected_checksum_names[@]}"; do
  [ "${actual_checksum_names[$index]}" = "${expected_checksum_names[$index]}" ] ||
    fail "outer checksum manifest has an unexpected record"
done
(
  cd "$stage/assets"
  /usr/bin/sha256sum --strict -c SHA256SUMS.txt >/dev/null
) || fail "successful stage is not checksum-closed"
[ -z "$(find "$tmp" -maxdepth 1 -type d -name '.release-*' -print -quit)" ] ||
  fail "successful stage left a private temporary directory"

if /usr/bin/env -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C TZ=UTC \
    HOME=/nonexistent TMPDIR=/tmp HAPTICS_STAGE_CLEAN_ENV=1 \
    UNEXPECTED_STAGE_ENV=1 BASH_ENV="$poison_dir/bash-env.sh" \
    /bin/bash -p "$SCRIPT_DIR/stage-haptics-release-assets.sh" \
      "$producer" "$tmp/forged-marker-stage" "${stage_args[@]}" >/dev/null 2>&1; then
  fail "forged clean-environment marker unexpectedly passed"
fi
[ ! -e "$tmp/forged-marker-stage" ] || fail "forged marker exposed a stage directory"
[ ! -e "$bash_env_marker" ] || fail "forged marker executed hostile BASH_ENV"

make_mutated_stage_scripts() {
  local mode=$1 destination=$2

  /usr/bin/mkdir -p -- "$destination"
  /usr/bin/cp -a --reflink=auto -- "$SCRIPT_DIR/." "$destination/"
  /usr/bin/python3 -I - "$destination/stage-haptics-release-assets.sh" "$mode" <<'PY_MUTATE'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
mode = sys.argv[2]
source = path.read_text(encoding="utf-8")
if mode == "second-allocation-failure":
    old = 'verification_root=$(/usr/bin/mktemp -d "$release_parent/.release-verification.XXXXXX")\n'
    new = 'verification_root=\n/bin/false\n'
elif mode == "final-verifier-failure":
    old = '/bin/bash -p "$SCRIPT_DIR/verify-haptics-publication-stage.sh" \\\n'
    new = '/usr/bin/printf "fixture-final-verifier-mutation\\n" >> "$notes"\n' + old
else:
    raise SystemExit(f"unknown stage mutation: {mode}")
if source.count(old) != 1:
    raise SystemExit(f"stage mutation boundary is not unique: {mode}")
path.write_text(source.replace(old, new), encoding="utf-8")
PY_MUTATE
}

allocation_scripts="$tmp/allocation-scripts"
make_mutated_stage_scripts second-allocation-failure "$allocation_scripts"
if /bin/bash -p "$allocation_scripts/stage-haptics-release-assets.sh" \
    "$producer" "$tmp/allocation-stage" "${stage_args[@]}" >/dev/null 2>&1; then
  fail "forced second temporary-directory allocation failure unexpectedly passed"
fi
[ ! -e "$tmp/allocation-stage" ] || fail "allocation failure exposed a stage directory"
[ -z "$(/usr/bin/find "$tmp" -maxdepth 1 -type d -name '.release-*' -print -quit)" ] ||
  fail "second allocation failure did not clean the first temporary directory"

final_verifier_scripts="$tmp/final-verifier-scripts"
make_mutated_stage_scripts final-verifier-failure "$final_verifier_scripts"
set +e
final_verifier_output=$(/bin/bash -p \
  "$final_verifier_scripts/stage-haptics-release-assets.sh" \
  "$producer" "$tmp/final-verifier-stage" "${stage_args[@]}" 2>&1)
final_verifier_status=$?
set -e
[ "$final_verifier_status" -ne 0 ] ||
  fail "mutation before the final publication verifier unexpectedly passed"
/usr/bin/grep -Fq 'haptics publication stage is not checksum-closed' \
  <<<"$final_verifier_output" ||
  fail "final publication verifier mutation failed at the wrong boundary: $final_verifier_output"
[ ! -e "$tmp/final-verifier-stage" ] ||
  fail "final publication verifier failure exposed a stage directory"
[ -z "$(/usr/bin/find "$tmp" -maxdepth 1 -type d -name '.release-*' -print -quit)" ] ||
  fail "final publication verifier failure left a private temporary directory"

bad_producer="$tmp/bad-producer"
cp -a --reflink=auto -- "$producer" "$bad_producer"
sed -i 's/^HAPTICS_PRODUCER_COMMIT=.*/HAPTICS_PRODUCER_COMMIT=0000000000000000000000000000000000000000/' \
  "$bad_producer/HAPTICS-COMPILED-DIGESTS.env"
if /bin/bash -p "$SCRIPT_DIR/stage-haptics-release-assets.sh" \
  "$bad_producer" "$tmp/bad-stage" "${stage_args[@]}" >/dev/null 2>&1; then
  fail "mismatched producer stage unexpectedly passed"
fi
[ ! -e "$tmp/bad-stage" ] || fail "failed stage exposed a partial final directory"
[ -z "$(find "$tmp" -maxdepth 1 -type d -name '.release-*' -print -quit)" ] ||
  fail "failed stage left a private temporary directory"

mkdir "$tmp/existing-stage"
printf 'preserve\n' > "$tmp/existing-stage/marker"
if /bin/bash -p "$SCRIPT_DIR/stage-haptics-release-assets.sh" \
  "$producer" "$tmp/existing-stage" "${stage_args[@]}" >/dev/null 2>&1; then
  fail "existing stage target unexpectedly passed"
fi
[ "$(cat "$tmp/existing-stage/marker")" = preserve ] ||
  fail "existing stage target was modified"

printf 'HAPTICS_RELEASE_STAGING_A12_ADAPTED=PASS\n'
