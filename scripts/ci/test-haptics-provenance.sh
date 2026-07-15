#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)
. "$SCRIPT_DIR/common.sh"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/tb321fu-haptics-provenance.XXXXXX")
cleanup() {
  rm -rf -- "$tmp"
}
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
  [ "$status" -ne 0 ] || fail "hostile provenance fixture unexpectedly passed"
  grep -Fq -- "$expected" <<<"$output" ||
    fail "hostile provenance fixture failed at the wrong boundary: $output"
}

fixture="$tmp/source"
git init -q "$fixture"
git -C "$fixture" config user.name 'TB321FU fixture'
git -C "$fixture" config user.email 'fixture@example.invalid'
printf '/out/\n' > "$fixture/.gitignore"
printf 'fixture\n' > "$fixture/source.txt"
git -C "$fixture" add .gitignore source.txt
git -C "$fixture" commit -q -m fixture
commit=$(git -C "$fixture" rev-parse HEAD)
exported="$tmp/exported/source.txt"

[ "$(ci_verify_clean_git_commit "$fixture" "$commit")" = "$commit" ] ||
  fail "clean exact producer commit was rejected"
ci_export_git_file "$fixture" "$commit" source.txt "$exported"
grep -Fxq fixture "$exported" || fail "Git blob export did not preserve committed bytes"
require_failure 'source commit mismatch' \
  ci_verify_clean_git_commit "$fixture" 0000000000000000000000000000000000000000

hostile_verified=$(
  GIT_DIR=/nonexistent \
  GIT_WORK_TREE=/nonexistent \
  GIT_COMMON_DIR=/nonexistent \
  GIT_INDEX_FILE=/nonexistent \
  GIT_OBJECT_DIRECTORY=/nonexistent \
  GIT_ALTERNATE_OBJECT_DIRECTORIES=/nonexistent \
  GIT_CONFIG_COUNT=1 \
  GIT_CONFIG_KEY_0=core.worktree \
  GIT_CONFIG_VALUE_0=/nonexistent \
  GIT_CONFIG_PARAMETERS=malformed \
  ci_verify_clean_git_commit "$fixture" "$commit"
)
[ "$hostile_verified" = "$commit" ] || fail "hostile Git environment changed commit verification"
GIT_DIR=/nonexistent \
GIT_WORK_TREE=/nonexistent \
GIT_COMMON_DIR=/nonexistent \
GIT_INDEX_FILE=/nonexistent \
GIT_OBJECT_DIRECTORY=/nonexistent \
GIT_ALTERNATE_OBJECT_DIRECTORIES=/nonexistent \
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.worktree \
GIT_CONFIG_VALUE_0=/nonexistent \
GIT_CONFIG_PARAMETERS=malformed \
ci_export_git_file "$fixture" "$commit" source.txt "$tmp/exported-hostile.txt"
grep -Fxq fixture "$tmp/exported-hostile.txt" ||
  fail "hostile Git environment changed blob export"

replacement_index="$tmp/replacement.index"
GIT_INDEX_FILE="$replacement_index" git -C "$fixture" read-tree "$commit^{tree}"
replacement_blob=$(printf 'replacement-object-tamper\n' | git -C "$fixture" hash-object -w --stdin)
GIT_INDEX_FILE="$replacement_index" git -C "$fixture" update-index \
  --add --cacheinfo "100644,$replacement_blob,source.txt"
replacement_tree=$(GIT_INDEX_FILE="$replacement_index" git -C "$fixture" write-tree)
replacement_commit=$(printf 'replacement fixture\n' | git -C "$fixture" commit-tree "$replacement_tree")
git -C "$fixture" replace "$commit" "$replacement_commit"
[ "$(git -C "$fixture" show "$commit:source.txt")" = replacement-object-tamper ] ||
  fail "replacement fixture did not affect ordinary Git"
ci_export_git_file "$fixture" "$commit" source.txt "$tmp/exported-replacement.txt"
grep -Fxq fixture "$tmp/exported-replacement.txt" ||
  fail "Git replacement object changed sanitized blob export"
git -C "$fixture" replace -d "$commit" >/dev/null

printf 'dirty\n' >> "$fixture/source.txt"
require_failure 'source worktree must be clean' \
  ci_verify_clean_git_commit "$fixture" "$commit"
printf 'fixture\n' > "$fixture/source.txt"

printf 'untracked\n' > "$fixture/untracked.txt"
require_failure 'source worktree must be clean' \
  ci_verify_clean_git_commit "$fixture" "$commit"
rm -f -- "$fixture/untracked.txt"

mkdir -p "$fixture/out"
printf 'ignored build output\n' > "$fixture/out/package.deb"
[ "$(ci_verify_clean_git_commit "$fixture" "$commit")" = "$commit" ] ||
  fail "ignored output directory made the producer appear dirty"

git -C "$fixture" update-index --assume-unchanged source.txt
printf 'assume-unchanged tamper\n' > "$fixture/source.txt"
require_failure 'unsafe assume-unchanged/skip-worktree index flags' \
  ci_verify_clean_git_commit "$fixture" "$commit"
ci_export_git_file "$fixture" "$commit" source.txt "$tmp/exported-assume.txt"
grep -Fxq fixture "$tmp/exported-assume.txt" ||
  fail "Git blob export consumed assume-unchanged worktree bytes"
printf 'fixture\n' > "$fixture/source.txt"
git -C "$fixture" update-index --no-assume-unchanged source.txt

git -C "$fixture" update-index --skip-worktree source.txt
printf 'skip-worktree tamper\n' > "$fixture/source.txt"
require_failure 'unsafe assume-unchanged/skip-worktree index flags' \
  ci_verify_clean_git_commit "$fixture" "$commit"
ci_export_git_file "$fixture" "$commit" source.txt "$tmp/exported-skip.txt"
grep -Fxq fixture "$tmp/exported-skip.txt" ||
  fail "Git blob export consumed skip-worktree bytes"
printf 'fixture\n' > "$fixture/source.txt"
git -C "$fixture" update-index --no-skip-worktree source.txt

history="$tmp/history"
git init -q "$history"
git -C "$history" config user.name 'TB321FU fixture'
git -C "$history" config user.email 'fixture@example.invalid'
printf 'one\n' > "$history/history.txt"
git -C "$history" add history.txt
git -C "$history" commit -q -m one
printf 'two\n' > "$history/history.txt"
git -C "$history" commit -q -am two
history_commit=$(git -C "$history" rev-parse HEAD)
bundle="$tmp/HAPTICS-PRODUCER.bundle"
bundle_ref=refs/heads/tb321fu-haptics-producer
ci_create_exact_git_bundle "$history" "$history_commit" "$bundle" "$bundle_ref"
verify_git="$tmp/bundle-verify.git"
ci_git init -q --bare "$verify_git"
ci_git --git-dir="$verify_git" bundle verify "$bundle" >/dev/null
[ "$(ci_git --git-dir="$verify_git" bundle list-heads "$bundle")" = "$history_commit $bundle_ref" ] ||
  fail "producer bundle does not expose exactly the fixed expected ref"

shallow="$tmp/shallow"
git clone -q --depth=1 "file://$history" "$shallow"
shallow_commit=$(git -C "$shallow" rev-parse HEAD)
require_failure 'self-contained Git bundle' \
  ci_create_exact_git_bundle "$shallow" "$shallow_commit" \
  "$tmp/shallow.bundle" "$bundle_ref"

expected_fields=(
  schema
  haptics-producer-commit
  haptics-producer-state
  aw86937-driver-sha256
  aw86937-build-source-sha256
  haptic-ram-firmware-sha256
  haptic-click-firmware-sha256
  haptic-test-helper-sha256
  aw86937-module-sha256
  haptic-test-helper-binary-sha256
  kernel-bundle-id
  kernel-release
  kernel-source-commit
  kernel-config-sha256
  kernel-build-archive-sha256
  source-date-epoch
)
previous_line=0
for token in "${expected_fields[@]}"; do
  line=$(grep -n -F "printf '$token\\t" \
    "$SCRIPT_DIR/build-tb321fu-haptics-deb.sh" | cut -d: -f1)
  [ -n "$line" ] || fail "builder omits source-lock field: $token"
  [ "$line" -gt "$previous_line" ] ||
    fail "builder source-lock field is out of canonical order: $token"
  previous_line=$line
done

for token in \
  ci_export_git_file \
  HAPTICS-SOURCE-SNAPSHOT \
  haptics-producer-commit \
  haptics-producer-state \
  aw86937-driver-sha256 \
  aw86937-build-source-sha256 \
  haptic-ram-firmware-sha256 \
  haptic-click-firmware-sha256 \
  haptic-test-helper-sha256 \
  aw86937-module-sha256 \
  haptic-test-helper-binary-sha256; do
  grep -Fq -- "$token" "$SCRIPT_DIR/build-tb321fu-haptics-deb.sh" ||
    fail "builder omits provenance boundary: $token"
done
grep -Fq 'verify_kernel_source_state "before package build"' \
  "$SCRIPT_DIR/build-tb321fu-haptics-deb.sh" ||
  fail "builder omits strict pre-build kernel source verification"
grep -Fq 'verify_kernel_source_state "after package build"' \
  "$SCRIPT_DIR/build-tb321fu-haptics-deb.sh" ||
  fail "builder omits strict post-build kernel source verification"
grep -Fq 'HAPTICS-SOURCE-SNAPSHOT' \
  "$SCRIPT_DIR/build-tb321fu-haptics-deb-from-kernel-sdk.sh" ||
  fail "outer haptics archive omits the source snapshot"
grep -Fq 'EXPECTED_HAPTICS_PRODUCER_COMMIT="$HAPTICS_PRODUCER_COMMIT"' \
  "$SCRIPT_DIR/build-tb321fu-haptics-deb-from-kernel-sdk.sh" ||
  fail "SDK wrapper does not bind the expected producer commit"
grep -Fq 'HAPTICS_PRODUCER_COMMIT="$GITHUB_SHA"' \
  "$REPO_ROOT/.github/workflows/build.yml" ||
  fail "workflow does not bind the producer commit to GITHUB_SHA"
grep -Fq 'fetch-depth: 0' "$REPO_ROOT/.github/workflows/build.yml" ||
  fail "workflow does not fetch complete producer history for the bundle"
grep -Fq 'ci_git show -s --format=%ct HEAD' "$REPO_ROOT/.github/workflows/build.yml" ||
  fail "workflow timestamp derivation bypasses sanitized Git"

sdk_script="$SCRIPT_DIR/build-tb321fu-haptics-deb-from-kernel-sdk.sh"
if grep -Fq './*.deb' "$sdk_script"; then
  fail "SDK wrapper still selects DEBs with a glob"
fi
for token in \
  'HAPTICS-PRODUCER.bundle' \
  'refs/heads/tb321fu-haptics-producer' \
  '.delivery.XXXXXX' \
  'refusing stale OUTPUT_DIR' \
  'OUTPUT_DIR appeared during atomic promotion' \
  'mv -T -- "$producer_output" "$output_path"' \
  'HAPTICS-COMPILED-DIGESTS.env' \
  'HAPTICS_MODULE_SHA256=' \
  'HAPTICS_HELPER_BINARY_SHA256='; do
  grep -Fq -- "$token" "$SCRIPT_DIR/build-tb321fu-haptics-deb.sh" "$sdk_script" ||
    fail "haptics production path omits contract token: $token"
done

python3 - "$sdk_script" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text()
start = source.index("archive_members=(")
end = source.index("\n)", start)
block = source[start:end]
expected = [
    '"$deb_name"',
    "HAPTICS-SOURCE-LOCK.tsv",
    "HAPTICS-PRODUCER.bundle",
    "HAPTICS-SOURCE-SNAPSHOT/source/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c",
    "HAPTICS-SOURCE-SNAPSHOT/build/aw86937-haptics.c",
    "HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_ram.bin",
    "HAPTICS-SOURCE-SNAPSHOT/source/haptics/rootfs-reference/usr/lib/firmware/haptic_click.bin",
    "HAPTICS-SOURCE-SNAPSHOT/source/haptics/baseline-20260614-daily-clean/testing-tools/y700-haptic-test.c",
    "SHA256SUMS-tb321fu-haptics-debs.txt",
]
actual = [line.strip() for line in block.splitlines()[1:] if line.strip()]
assert actual == expected, (actual, expected)
PY

stale_output="$tmp/stale-output"
mkdir "$stale_output"
require_failure 'refusing stale OUTPUT_DIR' \
  env \
    OUTPUT_DIR="$stale_output" \
    HAPTICS_PRODUCER_COMMIT=0000000000000000000000000000000000000000 \
    KERNEL_SOURCE_COMMIT=0000000000000000000000000000000000000000 \
    KERNEL_BUILD_ARCHIVE_SHA256=0000000000000000000000000000000000000000000000000000000000000000 \
    SOURCE_DATE_EPOCH=0 \
    bash "$sdk_script"

printf 'HAPTICS_PROVENANCE=PASS\n'
