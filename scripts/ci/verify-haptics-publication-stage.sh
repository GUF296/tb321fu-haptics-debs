#!/usr/bin/env bash
set -euo pipefail
umask 077

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
. "$SCRIPT_DIR/common.sh"
unset CI_CURL_BIN CI_ENV_BIN CI_GIT_BIN CI_PYTHON3_BIN CI_SHA256SUM_BIN
CI_GIT_BIN=/usr/bin/git
CI_ENV_BIN=/usr/bin/env
CI_CURL_BIN=/usr/bin/curl
CI_PYTHON3_BIN=/usr/bin/python3
CI_SHA256SUM_BIN=/usr/bin/sha256sum
PROVENANCE_VERIFIER="$SCRIPT_DIR/verify-haptics-release-provenance.py"

[ "$#" -eq 4 ] ||
  ci_die "usage: verify-haptics-publication-stage.sh RELEASE_DIR REFERENCE EXPECTED_PRODUCER_COMMIT EXTRACT_ROOT"

release_dir=$1
reference=$2
expected_producer=$3
extract_root=$4

[ -d "$release_dir" ] && [ ! -L "$release_dir" ] ||
  ci_die "haptics publication stage is not a real directory"
[ -f "$reference" ] && [ ! -L "$reference" ] ||
  ci_die "haptics release reference is not a regular file"
[[ $expected_producer =~ ^[0-9a-f]{40}$ ]] ||
  ci_die "expected haptics producer commit is not 40 lowercase hex"
[ ! -e "$extract_root" ] && [ ! -L "$extract_root" ] ||
  ci_die "haptics publication verification root already exists"

release_dir=$(realpath -e -- "$release_dir")
reference=$(realpath -e -- "$reference")
extract_parent=$(dirname -- "$extract_root")
mkdir -p -- "$extract_parent"
extract_parent=$(realpath -e -- "$extract_parent")
extract_root="$extract_parent/$(basename -- "$extract_root")"
reference_snapshot="$extract_parent/HAPTICS-RELEASE-REFERENCE.snapshot.tsv"
[ ! -e "$reference_snapshot" ] && [ ! -L "$reference_snapshot" ] ||
  ci_die "haptics release reference snapshot already exists"
/usr/bin/python3 -I "$SCRIPT_DIR/verify-haptics-release-reference.py" \
  --emit-tsv "$reference" > "$reference_snapshot"
chmod 0400 "$reference_snapshot"
reference=$reference_snapshot
[ -f "$PROVENANCE_VERIFIER" ] && [ ! -L "$PROVENANCE_VERIFIER" ] ||
  ci_die "haptics release provenance verifier is missing or unsafe"

reference_value() {
  local key=$1 count

  count=$(awk -F '\t' -v key="$key" '$1 == key { count++ } END { print count + 0 }' "$reference")
  [ "$count" -eq 1 ] || ci_die "haptics release reference key is not unique: $key"
  awk -F '\t' -v key="$key" '$1 == key { print $2 }' "$reference"
}

source_lock_value() {
  local key=$1 count

  count=$(awk -F '\t' -v key="$key" '$1 == key { count++ } END { print count + 0 }' "$source_lock")
  [ "$count" -eq 1 ] || ci_die "haptics source-lock key is not unique: $key"
  awk -F '\t' -v key="$key" '$1 == key { print $2 }' "$source_lock"
}

reference_producer=$(reference_value reference-producer-commit)
reference_version=$(reference_value package-version)
reference_bundle=$(reference_value kernel-bundle-id)
reference_toolchain=$(reference_value kernel-toolchain-manifest-sha256)
reference_kernel_archive_url=$(reference_value kernel-build-archive-url)
reference_bundle_url=$(reference_value kernel-bundle-metadata-url)
reference_bundle_sha=$(reference_value kernel-bundle-metadata-sha256)
reference_sdk_manifest_url=$(reference_value kernel-sdk-manifest-url)
reference_toolchain_url=$(reference_value kernel-toolchain-manifest-url)
reference_kernel_source=$(reference_value kernel-source-commit)
reference_kernel_archive=$(reference_value kernel-build-archive-sha256)
reference_deb=$(reference_value haptics-deb-sha256)
reference_module=$(reference_value haptics-module-sha256)
reference_helper=$(reference_value haptics-helper-sha256)
reference_archive=$(reference_value reference-archive-sha256)

[ "$reference_version" != "" ]
release_snapshot="$extract_parent/HAPTICS-PUBLICATION-STAGE.snapshot"
/usr/bin/python3 -I "$SCRIPT_DIR/snapshot-haptics-publication-stage.py" \
  "$release_dir" "$release_dir/BUILD-PARAMETERS.md" "$reference_version" \
  "$release_snapshot" || ci_die "cannot snapshot the exact haptics publication stage"
release_dir=$release_snapshot
/usr/bin/python3 -I - "$release_dir" "$reference_version" <<'PY_CHECKSUMS' ||
from __future__ import annotations

import hashlib
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
version = sys.argv[2]
expected = (
    f"tb321fu-haptics-debs_{version}_arm64.tar.gz",
    "HAPTICS-SOURCE-LOCK.tsv",
    "SHA256SUMS-tb321fu-haptics-debs.txt",
    "BUILD-PARAMETERS.md",
)
manifest = root / "SHA256SUMS.txt"
raw = manifest.read_bytes()
if not raw or len(raw) > 65536 or not raw.endswith(b"\n"):
    raise SystemExit("outer checksum manifest is empty, oversized, or unterminated")
try:
    lines = raw.decode("ascii").splitlines()
except UnicodeDecodeError as exc:
    raise SystemExit("outer checksum manifest is not ASCII") from exc
if len(lines) != len(expected):
    raise SystemExit("outer checksum manifest does not have exactly four records")
for line, name in zip(lines, expected, strict=True):
    match = re.fullmatch(r"([0-9a-f]{64})  ([0-9A-Za-z._+-]+)", line)
    if match is None or match.group(2) != name:
        raise SystemExit(f"outer checksum manifest has an invalid record for {name}")
    digest = hashlib.sha256((root / name).read_bytes()).hexdigest()
    if digest != match.group(1):
        raise SystemExit(f"outer checksum mismatch for {name}")
PY_CHECKSUMS
  ci_die "haptics publication stage is not checksum-closed"
archive="$release_dir/tb321fu-haptics-debs_${reference_version}_arm64.tar.gz"
source_lock="$release_dir/HAPTICS-SOURCE-LOCK.tsv"
package_checksums="$release_dir/SHA256SUMS-tb321fu-haptics-debs.txt"
for path in "$archive" "$source_lock" "$package_checksums"; do
  [ -f "$path" ] && [ ! -L "$path" ] ||
    ci_die "haptics publication input is not a regular file: ${path##*/}"
done

mkdir -p -- "$(dirname -- "$extract_root")"
inner_deb=$(/bin/bash -p "$SCRIPT_DIR/verify-haptics-release-archive.sh" \
  "$archive" - "$reference_version" "$extract_root")
cmp -s -- "$source_lock" "$extract_root/HAPTICS-SOURCE-LOCK.tsv" ||
  ci_die "staged haptics source lock differs from the archive"
cmp -s -- "$package_checksums" "$extract_root/SHA256SUMS-tb321fu-haptics-debs.txt" ||
  ci_die "staged haptics package checksums differ from the archive"

[ "$(source_lock_value schema)" = tb321fu.haptics-source-lock/v4 ] ||
  ci_die "published haptics source lock is not release schema v4"
[ "$(source_lock_value haptics-output-mode)" = release-candidate ] ||
  ci_die "published haptics source lock is not a release candidate"
[ "$(source_lock_value haptics-producer-state)" = clean ] ||
  ci_die "published haptics producer state is not clean"
[ "$(source_lock_value haptics-producer-commit)" = "$expected_producer" ] ||
  ci_die "published haptics producer differs from the expected commit"
[ "$(source_lock_value kernel-bundle-id)" = "$reference_bundle" ] ||
  ci_die "published haptics kernel bundle differs from the trusted reference"
[ "$(source_lock_value kernel-toolchain-manifest-sha256)" = "$reference_toolchain" ] ||
  ci_die "published haptics toolchain manifest differs from the trusted reference"
[ "$(source_lock_value aw86937-module-sha256)" = "$reference_module" ] ||
  ci_die "published haptics module differs from the trusted reference"
[ "$(source_lock_value haptic-test-helper-binary-sha256)" = "$reference_helper" ] ||
  ci_die "published haptics helper differs from the trusted reference"
actual_deb=$(sha256sum -- "$inner_deb" | awk '{ print $1 }')
[ "$actual_deb" = "$reference_deb" ] ||
  ci_die "published haptics DEB differs from the trusted reference"

/usr/bin/python3 -I "$PROVENANCE_VERIFIER" \
  "$extract_root" "$reference_version" "$expected_producer" "$reference" ||
  ci_die "published haptics provenance archive is invalid"

bundle="$extract_root/HAPTICS-PRODUCER.bundle"
bundle_ref=refs/heads/tb321fu-haptics-producer
bundle_repo="$extract_parent/haptics-producer.git"
[ ! -e "$bundle_repo" ] && [ ! -L "$bundle_repo" ] ||
  ci_die "haptics bundle verification repository already exists"
ci_git init -q --bare "$bundle_repo"
ci_git_with_timeout /usr/bin/timeout 30 --git-dir="$bundle_repo" \
  bundle verify "$bundle" >/dev/null ||
  ci_die "haptics producer bundle is not self-contained and valid"
bundle_heads=$(ci_git_with_timeout /usr/bin/timeout 30 --git-dir="$bundle_repo" \
  bundle list-heads "$bundle") ||
  ci_die "cannot list haptics producer bundle heads"
[ "$bundle_heads" = "$expected_producer $bundle_ref" ] ||
  ci_die "haptics producer bundle does not expose the exact producer ref"
unbundled_heads=$(ci_git_with_timeout /usr/bin/timeout 30 --git-dir="$bundle_repo" \
  bundle unbundle "$bundle") ||
  ci_die "cannot import haptics producer bundle objects"
[ "$unbundled_heads" = "$bundle_heads" ] ||
  ci_die "haptics producer bundle heads changed during import"
ci_git_with_timeout /usr/bin/timeout 30 --git-dir="$bundle_repo" \
  cat-file -e "$expected_producer^{commit}" ||
  ci_die "haptics producer bundle omits the expected commit"
ci_git_with_timeout /usr/bin/timeout 30 --git-dir="$bundle_repo" \
  update-ref "$bundle_ref" "$expected_producer"
ci_git_with_timeout /usr/bin/timeout 30 --git-dir="$bundle_repo" \
  symbolic-ref HEAD "$bundle_ref"
fsck_output=$(ci_git_with_timeout /usr/bin/timeout 30 --git-dir="$bundle_repo" \
  fsck --full --strict --no-reflogs --unreachable 2>&1) ||
  ci_die "haptics producer bundle fails strict object verification"
[ -z "$fsck_output" ] || {
  printf '%s\n' "$fsck_output" >&2
  ci_die "haptics producer bundle contains unreachable or unexpected objects"
}

bundle_epoch=$(ci_git_with_timeout /usr/bin/timeout 30 --git-dir="$bundle_repo" \
  show -s --format=%ct "$expected_producer") ||
  ci_die "cannot read the haptics producer commit epoch"
[[ $bundle_epoch =~ ^[0-9]{1,11}$ ]] && [ "$bundle_epoch" -le 15032385535 ] &&
  [ "$bundle_epoch" = "$(source_lock_value source-date-epoch)" ] ||
  ci_die "haptics source epoch differs from the producer commit"

blob_index=0
while IFS=$'\t' read -r git_path snapshot_path; do
  entry=$(ci_git_with_timeout /usr/bin/timeout 30 --git-dir="$bundle_repo" \
    ls-tree "$expected_producer" -- "$git_path") ||
    ci_die "cannot inspect haptics producer source path: $git_path"
  IFS=$' \t' read -r entry_mode entry_type entry_object entry_path <<< "$entry"
  [ "$entry_mode" = 100644 ] && [ "$entry_type" = blob ] &&
    [[ $entry_object =~ ^[0-9a-f]{40}$ ]] && [ "$entry_path" = "$git_path" ] ||
    ci_die "haptics producer source path is not one exact 100644 blob: $git_path"
  blob_size=$(ci_git_with_timeout /usr/bin/timeout 30 --git-dir="$bundle_repo" \
    cat-file -s "$entry_object") ||
    ci_die "cannot size haptics producer source blob: $git_path"
  [[ $blob_size =~ ^[0-9]+$ ]] && [ "$blob_size" -le 1048576 ] ||
    ci_die "haptics producer source blob is oversized: $git_path"
  blob_index=$((blob_index + 1))
  blob="$extract_parent/haptics-source-blob.$blob_index"
  ci_git_with_timeout /usr/bin/timeout 30 --git-dir="$bundle_repo" cat-file blob \
    "$expected_producer:$git_path" > "$blob" ||
    ci_die "haptics producer bundle omits source blob: $git_path"
  cmp -s -- "$blob" "$extract_root/$snapshot_path" ||
    ci_die "haptics source snapshot differs from producer Git blob: $git_path"
done <<'EOF_BLOBS'
haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c	HAPTICS-SOURCE-SNAPSHOT/source/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c
haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin	HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin
haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin	HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin
haptics/baseline-20260614-daily-clean/testing-tools/y700-haptic-test.c	HAPTICS-SOURCE-SNAPSHOT/source/haptics/baseline-20260614-daily-clean/testing-tools/y700-haptic-test.c
EOF_BLOBS

generated_build_source="$extract_parent/aw86937-haptics.generated.c"
/usr/bin/cp -- "$extract_parent/haptics-source-blob.1" "$generated_build_source"
/usr/bin/sed -i \
  -e 's/Lenovo Y700 AW86937 input force-feedback haptics driver/Lenovo TB321FU AW86937 input force-feedback haptics driver/g' \
  -e 's/\.name = "aw86937-y700"/.name = "aw86937-haptics"/g' \
  "$generated_build_source"
if ! /usr/bin/grep -q '"aw86937_haptics"' "$generated_build_source"; then
  /usr/bin/sed -i '/{ "aw86937_y700" }/i\	{ "aw86937_haptics" },' \
    "$generated_build_source"
fi
/usr/bin/cmp -s -- "$generated_build_source" \
  "$extract_root/HAPTICS-SOURCE-SNAPSHOT/build/aw86937-haptics.c" ||
  ci_die "haptics build source is not the deterministic Git-driver transformation"

notes="$release_dir/BUILD-PARAMETERS.md"
[ -f "$notes" ] && [ ! -L "$notes" ] &&
  [ "$(stat -c '%s' -- "$notes")" -le 65536 ] ||
  ci_die "haptics release notes are missing or oversized"
/usr/bin/python3 -I - "$notes" <<'PY_NOTES' ||
import pathlib
import sys

raw = pathlib.Path(sys.argv[1]).read_bytes()
if not raw or len(raw) > 65536 or not raw.endswith(b"\n"):
    raise SystemExit("release notes must be nonempty, bounded, and LF-terminated")
if any(byte not in (9, 10) and not 32 <= byte <= 126 for byte in raw):
    raise SystemExit("release notes contain a non-printable byte")
lines = raw.decode("ascii").splitlines()
keys = (
    "Package version",
    "Kernel source commit",
    "Kernel SDK",
    "Kernel SDK SHA-256",
    "Kernel bundle metadata",
    "Kernel bundle metadata SHA-256",
    "Kernel bundle ID",
    "Kernel SDK manifest",
    "Kernel toolchain manifest",
    "Kernel toolchain manifest SHA-256",
    "Commit",
    "Workflow run",
    "Haptics archive SHA-256",
    "Haptics DEB SHA-256",
    "Haptics source lock SHA-256",
    "Trusted reference producer",
    "Trusted reference archive SHA-256",
    "Trusted reference DEB SHA-256",
    "Candidate HAPTICS_MODULE_SHA256",
    "Candidate HAPTICS_HELPER_BINARY_SHA256",
)
if len(lines) != 25 or lines[:2] != ["# TB321FU Haptics Debs", ""]:
    raise SystemExit("release notes do not have the exact header and line count")
for key, line in zip(keys, lines[2:22], strict=True):
    prefix = f"- {key}: "
    if not line.startswith(prefix) or line == prefix:
        raise SystemExit(f"release notes have an invalid or out-of-order field: {key}")
if lines[22:] != [
    "",
    "Static CI verifies package/lifecycle behavior; stop/suspend/resume remains a device gate.",
    "Compiled digests require a byte-identical second trusted build and independent consumer pinning.",
]:
    raise SystemExit("release notes do not have the exact evidence footer")
PY_NOTES
  ci_die "haptics release notes must be bounded printable LF text"
actual_archive=$(sha256sum -- "$archive" | awk '{ print $1 }')
actual_lock=$(sha256sum -- "$source_lock" | awk '{ print $1 }')
require_note_line() {
  [ "$(grep -Fxc -- "$1" "$notes")" -eq 1 ] ||
    ci_die "haptics release notes omit or duplicate trusted evidence: $1"
}
require_note_line "- Package version: $reference_version"
require_note_line "- Kernel source commit: $reference_kernel_source"
require_note_line "- Kernel SDK: $reference_kernel_archive_url"
require_note_line "- Kernel SDK SHA-256: $reference_kernel_archive"
require_note_line "- Kernel bundle metadata: $reference_bundle_url"
require_note_line "- Kernel bundle metadata SHA-256: $reference_bundle_sha"
require_note_line "- Kernel bundle ID: $reference_bundle"
require_note_line "- Kernel SDK manifest: $reference_sdk_manifest_url"
require_note_line "- Kernel toolchain manifest: $reference_toolchain_url"
require_note_line "- Kernel toolchain manifest SHA-256: $reference_toolchain"
require_note_line "- Commit: $expected_producer"
[ "$(/usr/bin/grep -Ec '^- Workflow run: [1-9][0-9]{0,19}$' "$notes")" -eq 1 ] ||
  ci_die "haptics release notes contain an invalid workflow run"
require_note_line "- Haptics archive SHA-256: $actual_archive"
require_note_line "- Haptics DEB SHA-256: $reference_deb"
require_note_line "- Haptics source lock SHA-256: $actual_lock"
require_note_line "- Trusted reference producer: $reference_producer"
require_note_line "- Trusted reference archive SHA-256: $reference_archive"
require_note_line "- Trusted reference DEB SHA-256: $reference_deb"
require_note_line "- Candidate HAPTICS_MODULE_SHA256: $reference_module"
require_note_line "- Candidate HAPTICS_HELPER_BINARY_SHA256: $reference_helper"

ci_git -C "$(dirname -- "$SCRIPT_DIR")/.." cat-file -e "$reference_producer^{commit}" ||
  ci_die "trusted haptics reference producer is absent from local history"
ci_git -C "$(dirname -- "$SCRIPT_DIR")/.." merge-base --is-ancestor \
  "$reference_producer" "$expected_producer" ||
  ci_die "trusted haptics reference producer is not an ancestor"

printf '%s\n' "$inner_deb"
