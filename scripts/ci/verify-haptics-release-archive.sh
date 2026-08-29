#!/usr/bin/env bash
set -euo pipefail
umask 077

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
. "$SCRIPT_DIR/common.sh"
unset CI_CURL_BIN CI_ENV_BIN CI_GIT_BIN CI_PYTHON3_BIN CI_SHA256SUM_BIN
CI_ENV_BIN=/usr/bin/env
CI_GIT_BIN=/usr/bin/git
CI_CURL_BIN=/usr/bin/curl
CI_PYTHON3_BIN=/usr/bin/python3
CI_SHA256SUM_BIN=/usr/bin/sha256sum

[ "$#" -eq 4 ] ||
  ci_die "usage: verify-haptics-release-archive.sh ARCHIVE PRODUCER_OUTPUT_OR_DASH VERSION EXTRACT_ROOT"

archive=$1
producer_output=$2
version=$3
extract_root=$4

[[ $version =~ ^[0-9][0-9A-Za-z.+~_-]{0,63}$ ]] ||
  ci_die "unsafe haptics package version"
[ -f "$archive" ] && [ ! -L "$archive" ] ||
  ci_die "haptics release archive is not a regular file"
if [ "$producer_output" != - ]; then
  [ -d "$producer_output" ] && [ ! -L "$producer_output" ] ||
    ci_die "haptics producer output is not a real directory"
fi
[ ! -e "$extract_root" ] && [ ! -L "$extract_root" ] ||
  ci_die "haptics release extraction root already exists"

if [ "$producer_output" != - ]; then
  producer_output=$(realpath -e -- "$producer_output")
fi
extract_parent=$(dirname -- "$extract_root")
mkdir -p -- "$extract_parent"
extract_parent=$(realpath -e -- "$extract_parent")
extract_root="$extract_parent/$(basename -- "$extract_root")"
verification_dir=$(mktemp -d "${TMPDIR:-/tmp}/tb321fu-haptics-release-archive.XXXXXX")
expected=
cleanup() {
  [ -z "$expected" ] || rm -f -- "$expected"
  rm -rf -- "$verification_dir"
}
trap cleanup EXIT
archive_snapshot="$verification_dir/archive.tar.gz"
/usr/bin/python3 -I "$SCRIPT_DIR/snapshot-bounded-regular-file.py" \
  "$archive" "$archive_snapshot" 67108864 --mode 0644 ||
  ci_die "cannot snapshot the haptics release archive"
archive=$archive_snapshot

deb_name="tb321fu-haptics_${version}_arm64.deb"
members=(
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

expected=$(mktemp "${TMPDIR:-/tmp}/tb321fu-haptics-release-members.XXXXXX")
printf '%s\n' "${members[@]}" > "$expected"

if ! /usr/bin/timeout --signal=TERM --kill-after=5s 30s \
    /bin/bash -p -c 'ulimit -v 262144; exec /usr/bin/python3 -I - "$@"' \
    haptics-archive-verifier "$archive" "$expected" <<'PY'
from __future__ import annotations

import pathlib
import re
import stat
import sys
import tarfile
import io
import zlib

archive = pathlib.Path(sys.argv[1])
expected = pathlib.Path(sys.argv[2]).read_text(encoding="ascii").splitlines()
source_lock = None

def verify_stream_termination(path: pathlib.Path) -> None:
    expanded = bytearray()
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            expanded.extend(decompressor.decompress(chunk))
            if len(expanded) > 128 * 1024 * 1024:
                raise SystemExit("haptics release archive decompressed stream is oversized")
            if decompressor.eof and decompressor.unused_data:
                raise SystemExit("haptics release archive has trailing compressed bytes")
    if not decompressor.eof:
        raise SystemExit("haptics release archive gzip stream is truncated")
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as strict:
        for _ in strict:
            pass
        if expanded[strict.offset:].strip(b"\0"):
            raise SystemExit("haptics release archive has trailing tar bytes")

try:
    with tarfile.open(archive, mode="r|gz") as handle:
        members = []
        total = 0
        for member in handle:
            if len(members) == len(expected):
                raise SystemExit(
                    f"haptics release archive has more than {len(expected)} members"
                )
            name = expected[len(members)]
            if member.name != name:
                raise SystemExit(
                    f"haptics release archive member {len(members) + 1} must be "
                    f"{name}, found {member.name}"
                )
            if not member.isreg():
                raise SystemExit(f"haptics release archive member is not regular: {name}")
            if stat.S_IMODE(member.mode) != 0o644:
                raise SystemExit(
                    f"haptics release archive member mode is not 0644: {name}"
                )
            if member.uid != 0 or member.gid != 0:
                raise SystemExit(
                    f"haptics release archive member owner is not numeric root: {name}"
                )
            if member.size > 64 * 1024 * 1024:
                raise SystemExit(f"haptics release archive member is oversized: {name}")
            total += member.size
            if total > 128 * 1024 * 1024:
                raise SystemExit(
                    "haptics release archive members exceed the 128 MiB total limit"
                )
            if name == "HAPTICS-SOURCE-LOCK.tsv":
                if member.size > 65536:
                    raise SystemExit("haptics release source lock is oversized")
                extracted = handle.extractfile(member)
                if extracted is None:
                    raise SystemExit("haptics release source lock cannot be read")
                source_lock = extracted.read(65537)
                if len(source_lock) != member.size or len(source_lock) > 65536:
                    raise SystemExit("haptics release source lock size changed while reading")
            members.append((member.name, member.mtime))
except (OSError, tarfile.TarError) as exc:
    raise SystemExit(f"haptics release archive cannot be read: {exc}") from exc

if len(members) != len(expected):
    raise SystemExit(
        f"haptics release archive has {len(members)} members, expected {len(expected)}"
    )
if source_lock is None:
    raise SystemExit("haptics release archive omits its source lock")
verify_stream_termination(archive)
try:
    source_lock_lines = source_lock.decode("ascii").splitlines()
except UnicodeDecodeError as exc:
    raise SystemExit("haptics release source lock is not ASCII") from exc
schema_values = []
epoch_values = []
for line in source_lock_lines:
    fields = line.split("\t")
    if len(fields) == 2 and fields[0] == "schema":
        schema_values.append(fields[1])
    if len(fields) == 2 and fields[0] == "source-date-epoch":
        epoch_values.append(fields[1])
if schema_values != ["tb321fu.haptics-source-lock/v4"]:
    raise SystemExit("haptics release source lock is not exact schema v4")
if len(epoch_values) != 1 or re.fullmatch(r"[0-9]{1,11}", epoch_values[0]) is None:
    raise SystemExit("haptics release source-lock epoch is invalid")
epoch = int(epoch_values[0])
if epoch > 15032385535:
    raise SystemExit("haptics release source-lock epoch exceeds the filesystem limit")
for name, mtime in members:
    if isinstance(mtime, bool) or not isinstance(mtime, int) or mtime != epoch:
        raise SystemExit(
            f"haptics release archive member mtime differs from source-lock epoch: {name}"
        )
PY
then
  ci_die "haptics release archive header verification failed or exceeded its resource limit"
fi

ci_extract_archive "$archive" "$extract_root" >/dev/null

mapfile -t actual < <(find "$extract_root" -type f -printf '%P\n' | sort)
mapfile -t expected_sorted < <(printf '%s\n' "${members[@]}" | sort)
[ "${#actual[@]}" -eq "${#expected_sorted[@]}" ] ||
  ci_die "extracted haptics release archive has an unexpected file count"
for index in "${!expected_sorted[@]}"; do
  [ "${actual[$index]}" = "${expected_sorted[$index]}" ] ||
    ci_die "extracted haptics release archive has an unexpected file: ${actual[$index]}"
done
[ -z "$(find "$extract_root" -mindepth 1 ! -type d ! -type f -print -quit)" ] ||
  ci_die "extracted haptics release archive contains a non-regular member"

for member in "${members[@]}"; do
  extracted="$extract_root/$member"
  [ -f "$extracted" ] && [ ! -L "$extracted" ] ||
    ci_die "extracted haptics archive member is not regular: $member"
  [ "$(stat -c '%a' -- "$extracted")" = 644 ] ||
    ci_die "extracted haptics archive member mode differs: $member"
  if [ "$producer_output" != - ]; then
    produced="$producer_output/$member"
    [ -f "$produced" ] && [ ! -L "$produced" ] ||
      ci_die "producer haptics archive member is not regular: $member"
    cmp -s -- "$extracted" "$produced" ||
      ci_die "haptics release archive member differs from producer output: $member"
  fi
done

printf '%s\n' "$extract_root/$deb_name"
