#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
VERIFY="$SCRIPT_DIR/verify-haptics-release-archive.sh"
VERSION=20260730.2
DEB="tb321fu-haptics_${VERSION}_arm64.deb"
EPOCH=1785426471

fail() {
  printf 'test failure: %s\n' "$*" >&2
  exit 1
}

require_failure() {
  local expected=$1 output status
  shift
  set +e
  output=$("$@" 2>&1)
  status=$?
  set -e
  [ "$status" -ne 0 ] || fail "fixture unexpectedly succeeded"
  grep -Fq -- "$expected" <<<"$output" ||
    fail "fixture failed at the wrong boundary: $output"
}

root=$(mktemp -d "${TMPDIR:-/tmp}/tb321fu-haptics-release-archive.XXXXXX")
cleanup() {
  rm -rf -- "$root"
}
trap cleanup EXIT

producer="$root/producer"
mkdir -p \
  "$producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/daily-current/linux/drivers/input/misc" \
  "$producer/HAPTICS-SOURCE-SNAPSHOT/build" \
  "$producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware" \
  "$producer/HAPTICS-SOURCE-SNAPSHOT/source/haptics/baseline-20260614-daily-clean/testing-tools"

members=(
  "$DEB"
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
for member in "${members[@]}"; do
  mkdir -p -- "$(dirname -- "$producer/$member")"
  printf 'fixture %s\n' "$member" > "$producer/$member"
  chmod 0644 "$producer/$member"
done
{
  printf 'schema\ttb321fu.haptics-source-lock/v4\n'
  printf 'source-date-epoch\t%s\n' "$EPOCH"
} > "$producer/HAPTICS-SOURCE-LOCK.tsv"
chmod 0644 "$producer/HAPTICS-SOURCE-LOCK.tsv"

make_archive() {
  local source=$1 destination=$2
  (
    cd "$source"
    tar --format=gnu --mtime="@$EPOCH" --owner=0 --group=0 --numeric-owner \
      -czf "$destination" -- \
      "${members[@]}"
  )
  chmod 0644 "$destination"
}

archive="$root/canonical.tar.gz"
make_archive "$producer" "$archive"
inner=$(/bin/bash -p "$VERIFY" "$archive" "$producer" "$VERSION" "$root/canonical-extract")
[ "$inner" = "$root/canonical-extract/$DEB" ] ||
  fail "archive verifier returned an unexpected embedded DEB path"
cmp -s -- "$inner" "$producer/$DEB" || fail "verified embedded DEB bytes differ"

standalone=$(/bin/bash -p "$VERIFY" "$archive" - "$VERSION" "$root/standalone-extract")
[ "$standalone" = "$root/standalone-extract/$DEB" ] ||
  fail "standalone archive verifier returned an unexpected embedded DEB path"
cmp -s -- "$standalone" "$producer/$DEB" ||
  fail "standalone verified embedded DEB bytes differ"

mismatch="$root/mismatch"
cp -a -- "$producer" "$mismatch"
printf 'different embedded DEB\n' > "$mismatch/$DEB"
chmod 0644 "$mismatch/$DEB"
mismatch_archive="$root/mismatch.tar.gz"
make_archive "$mismatch" "$mismatch_archive"
require_failure 'archive member differs from producer output' \
  /bin/bash -p "$VERIFY" "$mismatch_archive" "$producer" "$VERSION" "$root/mismatch-extract"

extra="$root/extra"
cp -a -- "$producer" "$extra"
printf 'unexpected\n' > "$extra/unexpected.bin"
extra_archive="$root/extra.tar.gz"
(
  cd "$extra"
  tar --format=gnu --mtime="@$EPOCH" --owner=0 --group=0 --numeric-owner \
    -czf "$extra_archive" -- \
    "${members[@]}" unexpected.bin
)
chmod 0644 "$extra_archive"
require_failure 'more than 10 members' \
  /bin/bash -p "$VERIFY" "$extra_archive" "$producer" "$VERSION" "$root/extra-extract"

missing_archive="$root/missing.tar.gz"
(
  cd "$producer"
  tar --format=gnu --mtime="@$EPOCH" --owner=0 --group=0 --numeric-owner \
    -czf "$missing_archive" -- \
    "${members[@]:0:9}"
)
chmod 0644 "$missing_archive"
require_failure 'has 9 members, expected 10' \
  /bin/bash -p "$VERIFY" "$missing_archive" "$producer" "$VERSION" "$root/missing-extract"

reordered_archive="$root/reordered.tar.gz"
(
  cd "$producer"
  tar --format=gnu --mtime="@$EPOCH" --owner=0 --group=0 --numeric-owner \
    -czf "$reordered_archive" -- \
    "${members[1]}" "${members[0]}" "${members[@]:2}"
)
chmod 0644 "$reordered_archive"
require_failure 'archive member 1 must be' \
  /bin/bash -p "$VERIFY" "$reordered_archive" "$producer" "$VERSION" "$root/reordered-extract"

symlink_source="$root/symlink-source"
cp -a -- "$producer" "$symlink_source"
rm -f -- "$symlink_source/$DEB"
ln -s -- HAPTICS-SOURCE-LOCK.tsv "$symlink_source/$DEB"
symlink_member_archive="$root/symlink-member.tar.gz"
make_archive "$symlink_source" "$symlink_member_archive"
require_failure 'archive member is not regular' \
  /bin/bash -p "$VERIFY" "$symlink_member_archive" "$producer" "$VERSION" "$root/symlink-member-extract"

wrong_mode_source="$root/wrong-mode-source"
cp -a -- "$producer" "$wrong_mode_source"
chmod 0600 "$wrong_mode_source/${members[1]}"
wrong_mode_archive="$root/wrong-mode.tar.gz"
make_archive "$wrong_mode_source" "$wrong_mode_archive"
require_failure 'archive member mode is not 0644' \
  /bin/bash -p "$VERIFY" "$wrong_mode_archive" "$producer" "$VERSION" "$root/wrong-mode-extract"

wrong_mtime_archive="$root/wrong-mtime.tar.gz"
(
  cd "$producer"
  tar --format=gnu --mtime="@$((EPOCH + 1))" --owner=0 --group=0 --numeric-owner \
    -czf "$wrong_mtime_archive" -- "${members[@]}"
)
chmod 0644 "$wrong_mtime_archive"
require_failure 'archive member mtime differs from source-lock epoch' \
  /bin/bash -p "$VERIFY" "$wrong_mtime_archive" "$producer" "$VERSION" "$root/wrong-mtime-extract"

wrong_owner_archive="$root/wrong-owner.tar.gz"
(
  cd "$producer"
  tar --format=gnu --mtime="@$EPOCH" --owner=1 --group=0 --numeric-owner \
    -czf "$wrong_owner_archive" -- "${members[@]}"
)
chmod 0644 "$wrong_owner_archive"
require_failure 'archive member owner is not numeric root' \
  /bin/bash -p "$VERIFY" "$wrong_owner_archive" "$producer" "$VERSION" "$root/wrong-owner-extract"

wrong_group_archive="$root/wrong-group.tar.gz"
(
  cd "$producer"
  tar --format=gnu --mtime="@$EPOCH" --owner=0 --group=1 --numeric-owner \
    -czf "$wrong_group_archive" -- "${members[@]}"
)
chmod 0644 "$wrong_group_archive"
require_failure 'archive member owner is not numeric root' \
  /bin/bash -p "$VERIFY" "$wrong_group_archive" "$producer" "$VERSION" "$root/wrong-group-extract"

wrong_schema_source="$root/wrong-schema-source"
cp -a -- "$producer" "$wrong_schema_source"
sed -i 's#tb321fu.haptics-source-lock/v4#tb321fu.haptics-source-lock/v3#' \
  "$wrong_schema_source/HAPTICS-SOURCE-LOCK.tsv"
wrong_schema_archive="$root/wrong-schema.tar.gz"
make_archive "$wrong_schema_source" "$wrong_schema_archive"
require_failure 'source lock is not exact schema v4' \
  /bin/bash -p "$VERIFY" "$wrong_schema_archive" "$wrong_schema_source" "$VERSION" "$root/wrong-schema-extract"

duplicate_epoch_source="$root/duplicate-epoch-source"
cp -a -- "$producer" "$duplicate_epoch_source"
printf 'source-date-epoch\t%s\n' "$EPOCH" >> \
  "$duplicate_epoch_source/HAPTICS-SOURCE-LOCK.tsv"
duplicate_epoch_archive="$root/duplicate-epoch.tar.gz"
make_archive "$duplicate_epoch_source" "$duplicate_epoch_archive"
require_failure 'source-lock epoch is invalid' \
  /bin/bash -p "$VERIFY" "$duplicate_epoch_archive" "$duplicate_epoch_source" "$VERSION" "$root/duplicate-epoch-extract"

oversized_epoch_source="$root/oversized-epoch-source"
cp -a -- "$producer" "$oversized_epoch_source"
/usr/bin/awk -F '\t' -v OFS='\t' '
  $1 == "source-date-epoch" { $2 = "15032385536" }
  { print }
' "$oversized_epoch_source/HAPTICS-SOURCE-LOCK.tsv" > \
  "$oversized_epoch_source/HAPTICS-SOURCE-LOCK.tsv.next"
/usr/bin/chmod 0644 "$oversized_epoch_source/HAPTICS-SOURCE-LOCK.tsv.next"
/usr/bin/mv -T -- "$oversized_epoch_source/HAPTICS-SOURCE-LOCK.tsv.next" \
  "$oversized_epoch_source/HAPTICS-SOURCE-LOCK.tsv"
oversized_epoch_archive="$root/oversized-epoch.tar.gz"
make_archive "$oversized_epoch_source" "$oversized_epoch_archive"
require_failure 'source-lock epoch exceeds the filesystem limit' \
  /bin/bash -p "$VERIFY" "$oversized_epoch_archive" "$oversized_epoch_source" "$VERSION" "$root/oversized-epoch-extract"

many_header_archive="$root/many-headers.tar.gz"
python3 - "$many_header_archive" "${members[@]}" <<'PY'
import gzip
import io
import pathlib
import sys
import tarfile

destination = pathlib.Path(sys.argv[1])
members = sys.argv[2:]
with gzip.GzipFile(filename="", mode="wb", fileobj=destination.open("wb"), mtime=0) as compressed:
    with tarfile.open(fileobj=compressed, mode="w|") as archive:
        for name in members:
            info = tarfile.TarInfo(name)
            info.mode = 0o644
            info.size = 0
            archive.addfile(info, io.BytesIO())
        for index in range(4096):
            info = tarfile.TarInfo(f"extra-{index:05d}")
            info.mode = 0o644
            info.size = 0
            archive.addfile(info, io.BytesIO())
PY
chmod 0644 "$many_header_archive"
require_failure 'more than 10 members' \
  /bin/bash -p "$VERIFY" "$many_header_archive" "$producer" "$VERSION" "$root/many-header-extract"

oversized_header_archive="$root/oversized-header.tar.gz"
python3 - "$oversized_header_archive" "$DEB" <<'PY'
import gzip
import pathlib
import sys
import tarfile

info = tarfile.TarInfo(sys.argv[2])
info.mode = 0o644
info.size = 64 * 1024 * 1024 + 1
with gzip.GzipFile(filename="", mode="wb", fileobj=pathlib.Path(sys.argv[1]).open("wb"), mtime=0) as output:
    output.write(info.tobuf(format=tarfile.GNU_FORMAT))
    output.write(b"\0" * 1024)
PY
chmod 0644 "$oversized_header_archive"
require_failure 'archive member is oversized' \
  /bin/bash -p "$VERIFY" "$oversized_header_archive" "$producer" "$VERSION" "$root/oversized-header-extract"

archive_link="$root/archive-link.tar.gz"
ln -s -- "$archive" "$archive_link"
require_failure 'archive is not a regular file' \
  /bin/bash -p "$VERIFY" "$archive_link" "$producer" "$VERSION" "$root/archive-link-extract"
archive_fifo="$root/archive-fifo.tar.gz"
mkfifo "$archive_fifo"
require_failure 'archive is not a regular file' \
  /bin/bash -p "$VERIFY" "$archive_fifo" "$producer" "$VERSION" "$root/archive-fifo-extract"
archive_wrong_mode="$root/archive-wrong-mode.tar.gz"
cp -- "$archive" "$archive_wrong_mode"
chmod 0600 "$archive_wrong_mode"
early_failure_tmp="$root/early-failure-tmp"
mkdir -p -- "$early_failure_tmp"
require_failure 'source must be a regular mode-0644 file' \
  env TMPDIR="$early_failure_tmp" \
    /bin/bash -p "$VERIFY" "$archive_wrong_mode" "$producer" "$VERSION" "$root/archive-mode-extract"
[ -z "$(find "$early_failure_tmp" -mindepth 1 -print -quit)" ] ||
  fail 'early archive snapshot rejection left private temporary state'

printf 'HAPTICS_RELEASE_ARCHIVE=PASS\n'
