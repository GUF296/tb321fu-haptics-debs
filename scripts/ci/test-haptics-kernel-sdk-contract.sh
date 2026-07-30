#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
. "$SCRIPT_DIR/common.sh"
. "$SCRIPT_DIR/haptics-kernel-sdk-contract.sh"

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

download_fixture=$(mktemp -d "${TMPDIR:-/tmp}/tb321fu-haptics-download.XXXXXX")
cleanup_download_fixture() {
  rm -rf -- "$download_fixture"
}
trap cleanup_download_fixture EXIT

cat > "$download_fixture/git" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
: "${FAKE_GIT_COMMIT:?}"
: "${FAKE_GIT_COUNT:?}"
: "${FAKE_GIT_FAILURES:?}"
: "${FAKE_GIT_LOG:?}"
: "${FAKE_GIT_MODE:?}"
: "${FAKE_GIT_DEST:?}"
: "${FAKE_GIT_REPOSITORY_URL:?}"
: "${FAKE_HTTP_PROXY:?}"
: "${FAKE_HTTPS_PROXY:?}"

[ -z "${GIT_SSL_NO_VERIFY+x}" ] || exit 89
[ -z "${GIT_HTTP_LOW_SPEED_LIMIT+x}" ] || exit 89
[ -z "${GIT_HTTP_LOW_SPEED_TIME+x}" ] || exit 89
[ "${http_proxy-}" = "$FAKE_HTTP_PROXY" ] || exit 89
[ "${https_proxy-}" = "$FAKE_HTTPS_PROXY" ] || exit 89

raw=("$@")
command=
for argument in "${raw[@]}"; do
  case "$argument" in
    init|remote|fetch|checkout|rev-parse)
      [ -z "$command" ] || exit 90
      command=$argument
      ;;
  esac
done
[ -n "$command" ] || exit 90

common=(
  --no-replace-objects
  -c core.fsmonitor=false
  -c core.untrackedCache=false
  -c core.excludesFile=/dev/null
)
case "$command" in
  init)
    expected=("${common[@]}" init -q "$FAKE_GIT_DEST")
    ;;
  remote)
    expected=("${common[@]}" -C "$FAKE_GIT_DEST" remote add origin "$FAKE_GIT_REPOSITORY_URL")
    ;;
  fetch)
    expected=(
      "${common[@]}"
      -C "$FAKE_GIT_DEST"
      -c http.version=HTTP/1.1
      -c http.followRedirects=false
      -c http.lowSpeedLimit=1024
      -c http.lowSpeedTime=300
      fetch --depth 1 --no-tags --recurse-submodules=no origin "$FAKE_GIT_COMMIT"
    )
    ;;
  checkout)
    expected=("${common[@]}" -C "$FAKE_GIT_DEST" checkout -q --detach FETCH_HEAD)
    ;;
  rev-parse)
    expected=("${common[@]}" -C "$FAKE_GIT_DEST" rev-parse HEAD)
    ;;
esac
[ "${#raw[@]}" -eq "${#expected[@]}" ] || exit 90
for index in "${!expected[@]}"; do
  [ "${raw[$index]}" = "${expected[$index]}" ] || exit 90
done
printf '%s\t%s\n' "$command" "$FAKE_GIT_DEST" >> "$FAKE_GIT_LOG"

repo=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --no-replace-objects)
      shift
      ;;
    -C)
      repo=$2
      shift 2
      ;;
    -c)
      shift 2
      ;;
    init|remote|fetch|checkout|rev-parse)
      command=$1
      shift
      break
      ;;
    *) exit 90 ;;
  esac
done

case "$command" in
  init)
    [ "$#" -eq 2 ] && [ "$1" = -q ] || exit 91
    repo=$2
    [ ! -e "$repo" ] || exit 92
    mkdir -p "$repo/.git"
    [ "$FAKE_GIT_MODE" != init-fail ] || exit 101
    ;;
  remote)
    [ -d "$repo/.git" ] || exit 93
    [ "$#" -eq 3 ] && [ "$1" = add ] && [ "$2" = origin ] || exit 94
    printf '%s\n' "$3" > "$repo/.git/origin-url"
    [ "$FAKE_GIT_MODE" != remote-fail ] || exit 102
    ;;
  fetch)
    [ -d "$repo/.git" ] || exit 95
    [ "$#" -eq 6 ] && [ "$1" = --depth ] && [ "$2" = 1 ] &&
      [ "$3" = --no-tags ] && [ "$4" = --recurse-submodules=no ] &&
      [ "$5" = origin ] && [ "$6" = "$FAKE_GIT_COMMIT" ] || exit 97
    [ "$(cat "$repo/.git/origin-url")" = "$FAKE_GIT_REPOSITORY_URL" ] || exit 97
    [ ! -e "$repo/.git/partial-object" ] || exit 98
    count=0
    [ ! -f "$FAKE_GIT_COUNT" ] || read -r count < "$FAKE_GIT_COUNT"
    count=$((count + 1))
    printf '%s\n' "$count" > "$FAKE_GIT_COUNT"
    if [ "$count" -le "$FAKE_GIT_FAILURES" ]; then
      printf 'incomplete\n' > "$repo/.git/partial-object"
      exit 56
    fi
    printf '%s\n' "$FAKE_GIT_COMMIT" > "$repo/.git/fetched-commit"
    ;;
  checkout)
    [ "$#" -eq 3 ] && [ "$1" = -q ] && [ "$2" = --detach ] && [ "$3" = FETCH_HEAD ] || exit 99
    [ "$FAKE_GIT_MODE" != checkout-fail ] || exit 103
    cp -- "$repo/.git/fetched-commit" "$repo/.git/head-commit"
    ;;
  rev-parse)
    [ "$#" -eq 1 ] && [ "$1" = HEAD ] || exit 100
    [ "$FAKE_GIT_MODE" != rev-parse-fail ] || exit 104
    if [ "$FAKE_GIT_MODE" = mismatch ]; then
      printf '0000000000000000000000000000000000000000\n'
    else
      cat -- "$repo/.git/head-commit"
    fi
    ;;
esac
SH
cat > "$download_fixture/timeout" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
: "${FAKE_TIMEOUT_LOG:?}"
[ "$#" -ge 5 ] || exit 110
[ "$1" = --signal=TERM ] || exit 111
[ "$2" = --kill-after=30s ] || exit 112
[ "$3" = 600s ] || exit 113
printf '%s\n' "$1" "$2" "$3" >> "$FAKE_TIMEOUT_LOG"
shift 3
exec "$@"
SH
cat > "$download_fixture/sleep" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
: "${FAKE_SLEEP_LOG:?}"
[ "$#" -eq 1 ] || exit 120
case "$1" in
  1|2|3) ;;
  *) exit 121 ;;
esac
printf '%s\n' "$1" >> "$FAKE_SLEEP_LOG"
SH
chmod 0700 "$download_fixture/git" "$download_fixture/timeout" "$download_fixture/sleep"

fake_git_commit=570b90203d97f67321fa0fb2d0af73c31d7111af
run_fake_git_fetch() {
  local destination=$1 failures=$2 mode=$3

  CI_GIT_BIN="$download_fixture/git" \
    FAKE_GIT_COMMIT="$fake_git_commit" \
    FAKE_GIT_COUNT="$download_fixture/git.count" \
    FAKE_GIT_DEST="$destination" \
    FAKE_GIT_FAILURES="$failures" \
    FAKE_GIT_LOG="$download_fixture/git.log" \
    FAKE_GIT_MODE="$mode" \
    FAKE_GIT_REPOSITORY_URL=https://example.invalid/kernel.git \
    FAKE_HTTP_PROXY=http://proxy.example.invalid:8080 \
    FAKE_HTTPS_PROXY=http://proxy.example.invalid:8443 \
    FAKE_SLEEP_LOG="$download_fixture/sleep.log" \
    FAKE_TIMEOUT_LOG="$download_fixture/timeout.log" \
    GIT_SSL_NO_VERIFY=1 \
    GIT_HTTP_LOW_SPEED_LIMIT=999999 \
    GIT_HTTP_LOW_SPEED_TIME=0 \
    http_proxy=http://proxy.example.invalid:8080 \
    https_proxy=http://proxy.example.invalid:8443 \
    ci_fetch_exact_git_commit \
      https://example.invalid/kernel.git \
      "$fake_git_commit" \
      "$destination" \
      4 \
      "$download_fixture/timeout" \
      "$download_fixture/sleep"
}

rm -f -- "$download_fixture/git.count" "$download_fixture/git.log" \
  "$download_fixture/sleep.log" "$download_fixture/timeout.log"
run_fake_git_fetch "$download_fixture/kernel-retry" 2 success
[ "$(cat "$download_fixture/git.count")" = 3 ] ||
  fail 'Git fetch retry did not stop after the first successful clean attempt'
[ -d "$download_fixture/kernel-retry/.git" ] &&
  [ ! -e "$download_fixture/kernel-retry/.git/partial-object" ] ||
  fail 'Git fetch retry retained a partial object from a failed repository'
cat > "$download_fixture/git.expected" <<EOF
init	$download_fixture/kernel-retry
remote	$download_fixture/kernel-retry
fetch	$download_fixture/kernel-retry
init	$download_fixture/kernel-retry
remote	$download_fixture/kernel-retry
fetch	$download_fixture/kernel-retry
init	$download_fixture/kernel-retry
remote	$download_fixture/kernel-retry
fetch	$download_fixture/kernel-retry
checkout	$download_fixture/kernel-retry
rev-parse	$download_fixture/kernel-retry
EOF
cmp -- "$download_fixture/git.expected" "$download_fixture/git.log" ||
  fail 'Git fetch retry did not use the exact fresh-repository command sequence'
mapfile -t retry_paths < <(
  find "$download_fixture" -mindepth 1 -maxdepth 1 -name 'kernel-retry*' -print | sort
)
[ "${#retry_paths[@]}" -eq 1 ] &&
  [ "${retry_paths[0]}" = "$download_fixture/kernel-retry" ] ||
  fail 'Git fetch retry left an unexpected sibling repository'
[ "$(cat "$download_fixture/sleep.log")" = $'1\n2' ] ||
  fail 'Git fetch retry did not apply the exact bounded backoff'
[ "$(wc -l < "$download_fixture/timeout.log")" -eq 9 ] ||
  fail 'Git fetch retry did not wrap every fetch in the exact timeout contract'

rm -rf -- "$download_fixture/kernel-retry"
rm -f -- "$download_fixture/git.count" "$download_fixture/git.log" \
  "$download_fixture/sleep.log" "$download_fixture/timeout.log"
require_failure 'Git fetch failed after 4 attempts' \
  run_fake_git_fetch "$download_fixture/kernel-exhausted" 9 success
[ "$(cat "$download_fixture/git.count")" = 4 ] ||
  fail 'Git fetch exhaustion did not stop at the fixed attempt bound'
if find "$download_fixture" -mindepth 1 -maxdepth 1 \
    -name 'kernel-exhausted*' -print -quit | grep -q .; then
  fail 'Git fetch exhaustion retained a failed or sibling repository'
fi
cat > "$download_fixture/git.expected" <<EOF
init	$download_fixture/kernel-exhausted
remote	$download_fixture/kernel-exhausted
fetch	$download_fixture/kernel-exhausted
init	$download_fixture/kernel-exhausted
remote	$download_fixture/kernel-exhausted
fetch	$download_fixture/kernel-exhausted
init	$download_fixture/kernel-exhausted
remote	$download_fixture/kernel-exhausted
fetch	$download_fixture/kernel-exhausted
init	$download_fixture/kernel-exhausted
remote	$download_fixture/kernel-exhausted
fetch	$download_fixture/kernel-exhausted
EOF
cmp -- "$download_fixture/git.expected" "$download_fixture/git.log" ||
  fail 'Git fetch exhaustion did not use the exact bounded command sequence'
[ "$(cat "$download_fixture/sleep.log")" = $'1\n2\n3' ] ||
  fail 'Git fetch exhaustion did not stop backoff before terminal failure'
[ "$(wc -l < "$download_fixture/timeout.log")" -eq 12 ] ||
  fail 'Git fetch exhaustion did not wrap exactly four fetches in timeouts'

rm -f -- "$download_fixture/git.count" "$download_fixture/git.log" \
  "$download_fixture/sleep.log" "$download_fixture/timeout.log"
require_failure 'Git fetch returned 0000000000000000000000000000000000000000' \
  run_fake_git_fetch "$download_fixture/kernel-mismatch" 0 mismatch
[ "$(cat "$download_fixture/git.count")" = 1 ] ||
  fail 'Git commit mismatch triggered a network retry'
if find "$download_fixture" -mindepth 1 -maxdepth 1 \
    -name 'kernel-mismatch*' -print -quit | grep -q .; then
  fail 'Git commit mismatch retained the rejected or sibling repository'
fi
cat > "$download_fixture/git.expected" <<EOF
init	$download_fixture/kernel-mismatch
remote	$download_fixture/kernel-mismatch
fetch	$download_fixture/kernel-mismatch
checkout	$download_fixture/kernel-mismatch
rev-parse	$download_fixture/kernel-mismatch
EOF
cmp -- "$download_fixture/git.expected" "$download_fixture/git.log" ||
  fail 'Git commit mismatch did not stop after the exact identity sequence'
[ ! -e "$download_fixture/sleep.log" ] ||
  fail 'Git commit mismatch triggered a retry delay'
[ "$(wc -l < "$download_fixture/timeout.log")" -eq 3 ] ||
  fail 'Git commit mismatch did not use exactly one fetch timeout'

for failure_mode in init-fail remote-fail checkout-fail rev-parse-fail; do
  failure_destination="$download_fixture/kernel-$failure_mode"
  rm -f -- "$download_fixture/git.count" "$download_fixture/git.log" \
    "$download_fixture/sleep.log" "$download_fixture/timeout.log"
  case "$failure_mode" in
    init-fail) expected_failure='cannot initialize Git fetch destination' ;;
    remote-fail) expected_failure='cannot configure Git fetch origin' ;;
    checkout-fail) expected_failure='cannot check out fetched Git commit' ;;
    rev-parse-fail) expected_failure='cannot resolve fetched Git commit' ;;
  esac
  require_failure "$expected_failure" \
    run_fake_git_fetch "$failure_destination" 0 "$failure_mode"
  if find "$download_fixture" -mindepth 1 -maxdepth 1 \
      -name "kernel-$failure_mode*" -print -quit | grep -q .; then
    fail "Git $failure_mode retained a failed or sibling repository"
  fi
  [ ! -e "$download_fixture/sleep.log" ] ||
    fail "Git $failure_mode triggered a retry delay"
done

mkdir "$download_fixture/real-parent"
ln -s "$download_fixture/real-parent" "$download_fixture/symlink-parent"
rm -f -- "$download_fixture/git.count" "$download_fixture/git.log" \
  "$download_fixture/sleep.log" "$download_fixture/timeout.log"
require_failure 'Git fetch destination parent must be a real directory' \
  run_fake_git_fetch "$download_fixture/symlink-parent/kernel" 0 success
[ ! -e "$download_fixture/real-parent/kernel" ] &&
  [ ! -e "$download_fixture/git.log" ] ||
  fail 'Git fetch accepted or invoked tools through a symlink parent'
printf 'PASS bounded exact Git fetch retries use fresh repositories\n'

printf 'complete pinned SDK bytes\n' > "$download_fixture/payload"
printf 'wrong bytes\n' > "$download_fixture/wrong-payload"
download_sha256=$(sha256sum "$download_fixture/payload" | awk '{print $1}')
cat > "$download_fixture/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
: "${FAKE_CURL_ARGS:?}"
: "${FAKE_CURL_COUNT:?}"
: "${FAKE_CURL_MODE:?}"
: "${FAKE_CURL_PAYLOAD:?}"
: "${FAKE_CURL_WRONG_PAYLOAD:?}"
count=0
if [ -f "$FAKE_CURL_COUNT" ]; then
  read -r count < "$FAKE_CURL_COUNT"
fi
count=$((count + 1))
printf '%s\n' "$count" > "$FAKE_CURL_COUNT"
printf '%s\n' "$@" > "$FAKE_CURL_ARGS.$count"
output=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output)
      [ "$#" -ge 2 ] || exit 2
      output=$2
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
[ -n "$output" ] || exit 2
case "$FAKE_CURL_MODE" in
  resume)
    case "$count" in
      1)
        head -c 8 -- "$FAKE_CURL_PAYLOAD" > "$output"
        exit 92
        ;;
      2)
        [ "$(head -c 8 -- "$output")" = "$(head -c 8 -- "$FAKE_CURL_PAYLOAD")" ] || exit 3
        offset=$(wc -c < "$output")
        tail -c "+$((offset + 1))" -- "$FAKE_CURL_PAYLOAD" >> "$output"
        ;;
      *) exit 4 ;;
    esac
    ;;
  range-reset)
    case "$count" in
      1)
        head -c 8 -- "$FAKE_CURL_PAYLOAD" > "$output"
        exit 92
        ;;
      2)
        [ -s "$output" ] || exit 5
        exit 33
        ;;
      3)
        [ ! -e "$output" ] || exit 6
        cp -- "$FAKE_CURL_PAYLOAD" "$output"
        ;;
      *) exit 7 ;;
    esac
    ;;
  complete-error)
    cp -- "$FAKE_CURL_PAYLOAD" "$output"
    exit 92
    ;;
  exhaust)
    head -c 8 -- "$FAKE_CURL_PAYLOAD" > "$output"
    exit 92
    ;;
  corrupt)
    cp -- "$FAKE_CURL_WRONG_PAYLOAD" "$output"
    ;;
  *) exit 8 ;;
esac
SH
chmod 0700 "$download_fixture/curl"
export FAKE_CURL_PAYLOAD="$download_fixture/payload"
export FAKE_CURL_WRONG_PAYLOAD="$download_fixture/wrong-payload"
export FAKE_CURL_ARGS="$download_fixture/curl-resume.args"
export FAKE_CURL_COUNT="$download_fixture/curl-resume.count"
export FAKE_CURL_MODE=resume
CI_CURL_BIN="$download_fixture/curl" ci_download \
  https://example.invalid/kernel-sdk.tar.gz \
  "$download_fixture/downloaded" \
  "$download_sha256"
cmp -- "$download_fixture/payload" "$download_fixture/downloaded" ||
  fail 'resumed HTTPS download did not promote the verified payload'
[ "$(cat "$FAKE_CURL_COUNT")" = 2 ] ||
  fail 'resumed HTTPS download used an unexpected attempt count'
python3 - "$FAKE_CURL_ARGS" "$download_fixture/downloaded.part.$$" <<'PY'
from pathlib import Path
import sys

expected = [
    "--disable",
    "--proto", "=https",
    "--proto-redir", "=https",
    "--tlsv1.2",
    "--http1.1",
    "--fail",
    "--location",
    "--connect-timeout", "30",
    "--max-time", "3600",
    "--speed-limit", "1024",
    "--speed-time", "300",
    "--continue-at", "-",
    "--output", sys.argv[2],
    "https://example.invalid/kernel-sdk.tar.gz",
]
logs = sorted(Path(sys.argv[1]).parent.glob(Path(sys.argv[1]).name + ".*"))
assert len(logs) == 2, logs
for log in logs:
    actual = log.read_text().splitlines()
    assert actual == expected, (log, actual, expected)
PY
[ ! -e "$download_fixture/downloaded.part.$$" ] ||
  fail 'verified HTTPS download left its private partial file behind'

export FAKE_CURL_ARGS="$download_fixture/curl-complete-error.args"
export FAKE_CURL_COUNT="$download_fixture/curl-complete-error.count"
export FAKE_CURL_MODE=complete-error
CI_CURL_BIN="$download_fixture/curl" ci_download \
  https://example.invalid/kernel-sdk.tar.gz \
  "$download_fixture/complete-error" \
  "$download_sha256"
cmp -- "$download_fixture/payload" "$download_fixture/complete-error" ||
  fail 'complete-before-error HTTPS download did not promote the verified payload'
[ "$(cat "$FAKE_CURL_COUNT")" = 1 ] ||
  fail 'complete-before-error HTTPS download performed a redundant retry'
[ ! -e "$download_fixture/complete-error.part.$$" ] ||
  fail 'complete-before-error HTTPS download left its private partial file behind'

export FAKE_CURL_ARGS="$download_fixture/curl-range.args"
export FAKE_CURL_COUNT="$download_fixture/curl-range.count"
export FAKE_CURL_MODE=range-reset
CI_CURL_BIN="$download_fixture/curl" ci_download \
  https://example.invalid/kernel-sdk.tar.gz \
  "$download_fixture/range-reset" \
  "$download_sha256"
cmp -- "$download_fixture/payload" "$download_fixture/range-reset" ||
  fail 'range-reset HTTPS download did not promote the verified payload'
[ "$(cat "$FAKE_CURL_COUNT")" = 3 ] ||
  fail 'range-reset HTTPS download used an unexpected attempt count'
[ ! -e "$download_fixture/range-reset.part.$$" ] ||
  fail 'range-reset HTTPS download left its private partial file behind'

require_failure 'download verification failed' env \
  CI_CURL_BIN="$download_fixture/curl" \
  FAKE_CURL_ARGS="$download_fixture/curl-corrupt.args" \
  FAKE_CURL_COUNT="$download_fixture/curl-corrupt.count" \
  FAKE_CURL_MODE=corrupt \
  FAKE_CURL_PAYLOAD="$download_fixture/payload" \
  FAKE_CURL_WRONG_PAYLOAD="$download_fixture/wrong-payload" \
  bash -c '. "$1"; ci_download "$2" "$3" "$4"' _ \
  "$SCRIPT_DIR/common.sh" \
  https://example.invalid/kernel-sdk.tar.gz \
  "$download_fixture/rejected" \
  "$download_sha256"
[ ! -e "$download_fixture/rejected" ] ||
  fail 'wrong-digest HTTPS payload was promoted'
if compgen -G "$download_fixture/rejected.part.*" >/dev/null; then
  fail 'wrong-digest HTTPS payload left a partial file behind'
fi

require_failure 'download failed after 24 attempts' env \
  CI_CURL_BIN="$download_fixture/curl" \
  FAKE_CURL_ARGS="$download_fixture/curl-exhaust.args" \
  FAKE_CURL_COUNT="$download_fixture/curl-exhaust.count" \
  FAKE_CURL_MODE=exhaust \
  FAKE_CURL_PAYLOAD="$download_fixture/payload" \
  FAKE_CURL_WRONG_PAYLOAD="$download_fixture/wrong-payload" \
  bash -c '. "$1"; ci_download "$2" "$3" "$4"' _ \
  "$SCRIPT_DIR/common.sh" \
  https://example.invalid/kernel-sdk.tar.gz \
  "$download_fixture/exhausted" \
  "$download_sha256"
[ "$(cat "$download_fixture/curl-exhaust.count")" = 24 ] ||
  fail 'exhausted HTTPS download did not stop at the fixed attempt limit'
[ ! -e "$download_fixture/exhausted" ] ||
  fail 'exhausted HTTPS download promoted a payload'
if compgen -G "$download_fixture/exhausted.part.*" >/dev/null; then
  fail 'exhausted HTTPS download left a partial file behind'
fi

ln -s payload "$download_fixture/local-link"
require_failure 'local download source is not a regular file' \
  bash -c '. "$1"; ci_download "$2" "$3"' _ \
  "$SCRIPT_DIR/common.sh" \
  "$download_fixture/local-link" \
  "$download_fixture/local-link-output"
[ ! -e "$download_fixture/local-link-output" ] ||
  fail 'symlink local download source was promoted'

archive_sha256=1111111111111111111111111111111111111111111111111111111111111111
metadata_sha256=2222222222222222222222222222222222222222222222222222222222222222
bundle_id=3333333333333333333333333333333333333333333333333333333333333333
archive_url=https://example.invalid/tb321fu-kernel-build-sdk.tar.gz
metadata_url=https://example.invalid/KERNEL-BUNDLE.tsv
manifest_url=https://example.invalid/KERNEL-SDK-MANIFEST.tsv

haptics_validate_kernel_build_input_contract \
  0 "" "" /tmp/private-kernel-build "" "" ""
haptics_validate_kernel_build_input_contract \
  1 "$archive_url" "$archive_sha256" "" "$metadata_url" "$metadata_sha256" "$manifest_url"
require_failure 'HAPTICS_RELEASE_MODE=0 requires KERNEL_BUILD_DIR' \
  haptics_validate_kernel_build_input_contract 0 "" "" "" "" "" ""
require_failure 'HAPTICS_RELEASE_MODE=0 forbids KERNEL_BUILD_ARCHIVE' \
  haptics_validate_kernel_build_input_contract 0 "$archive_url" "$archive_sha256" "" "" "" ""
require_failure 'HAPTICS_RELEASE_MODE=0 forbids KERNEL_SDK_MANIFEST' \
  haptics_validate_kernel_build_input_contract 0 "" "" /tmp/build "" "" "$manifest_url"
require_failure 'HAPTICS_RELEASE_MODE must be exactly 0 or 1' \
  haptics_validate_kernel_build_input_contract 2 "" "" /tmp/build "" "" ""
require_failure 'set exactly one of KERNEL_BUILD_ARCHIVE or KERNEL_BUILD_DIR' \
  haptics_validate_kernel_build_input_contract 0 "$archive_url" "$archive_sha256" /tmp/build "" "" ""
require_failure 'KERNEL_BUNDLE_METADATA and KERNEL_BUNDLE_METADATA_SHA256 must be provided together' \
  haptics_validate_kernel_build_input_contract 0 "" "" /tmp/build "$metadata_url" "" ""
require_failure 'HAPTICS_RELEASE_MODE=0 forbids KERNEL_SDK_MANIFEST' \
  haptics_validate_kernel_build_input_contract 0 "" "" /tmp/build "" "" "$manifest_url"
require_failure 'HAPTICS_RELEASE_MODE=1 requires KERNEL_BUILD_ARCHIVE' \
  haptics_validate_kernel_build_input_contract 1 "" "" "" "$metadata_url" "$metadata_sha256" "$manifest_url"
require_failure 'HAPTICS_RELEASE_MODE=1 requires KERNEL_BUNDLE_METADATA' \
  haptics_validate_kernel_build_input_contract 1 "$archive_url" "$archive_sha256" "" "" "" "$manifest_url"
require_failure 'HAPTICS_RELEASE_MODE=1 requires KERNEL_SDK_MANIFEST' \
  haptics_validate_kernel_build_input_contract 1 "$archive_url" "$archive_sha256" "" "$metadata_url" "$metadata_sha256" ""
require_failure 'HAPTICS_RELEASE_MODE=1 requires an HTTPS KERNEL_BUILD_ARCHIVE' \
  haptics_validate_kernel_build_input_contract 1 /tmp/kernel-sdk "$archive_sha256" "" "$metadata_url" "$metadata_sha256" "$manifest_url"
require_failure 'HAPTICS_RELEASE_MODE=1 requires HTTPS KERNEL_BUNDLE_METADATA' \
  haptics_validate_kernel_build_input_contract 1 "$archive_url" "$archive_sha256" "" /tmp/KERNEL-BUNDLE.tsv "$metadata_sha256" "$manifest_url"
require_failure 'HAPTICS_RELEASE_MODE=1 requires HTTPS KERNEL_SDK_MANIFEST' \
  haptics_validate_kernel_build_input_contract 1 "$archive_url" "$archive_sha256" "" "$metadata_url" "$metadata_sha256" /tmp/KERNEL-SDK-MANIFEST.tsv

haptics_validate_kernel_sdk_binding \
  1 kernel-sdk-archive "$archive_sha256" "$bundle_id" "$archive_sha256"
require_failure 'kernel SDK archive SHA-256 differs from KERNEL-BUNDLE.tsv' \
  haptics_validate_kernel_sdk_binding 1 kernel-sdk-archive "$archive_sha256" "$bundle_id" "$metadata_sha256"
require_failure 'KERNEL-BUNDLE.tsv lacks a valid kernel-sdk-archive-sha256' \
  haptics_validate_kernel_sdk_binding 1 kernel-sdk-archive "$archive_sha256" "$bundle_id" unbound
require_failure 'KERNEL-BUNDLE.tsv lacks a valid kernel-bundle-id' \
  haptics_validate_kernel_sdk_binding 1 kernel-sdk-archive "$archive_sha256" unbound "$archive_sha256"
require_failure 'HAPTICS_RELEASE_MODE=1 requires a kernel SDK archive input' \
  haptics_validate_kernel_sdk_binding 1 local-directory local-build-directory "$bundle_id" "$archive_sha256"
haptics_validate_kernel_sdk_binding \
  0 local-directory local-build-directory unbound unbound

identity_fixture="$download_fixture/prepare-kernel-kbuild-identity.sh"
awk '
  /^prepare_kernel_kbuild_identity\(\)/ { emit = 1 }
  emit { print }
  emit && /^}$/ { exit }
' "$SCRIPT_DIR/build-tb321fu-haptics-deb.sh" > "$identity_fixture"
[ -s "$identity_fixture" ] || fail "could not extract Kbuild identity preparation"
. "$identity_fixture"
haptics_run_isolated_tool() {
  [ "$1" = date ] || fail "Kbuild identity fixture invoked an unexpected tool: $1"
  shift
  /usr/bin/date "$@"
}

kernel_bundle_id=unbound
SOURCE_DATE_EPOCH=1784752597
kernel_kbuild_timestamp=
kernel_kbuild_user=
kernel_kbuild_host=
kernel_kbuild_version=
prepare_kernel_kbuild_identity
[ "$kernel_kbuild_timestamp" = '2026-07-22 20:36:37 UTC' ] ||
  fail "local Kbuild timestamp was not derived from SOURCE_DATE_EPOCH"
[ "$kernel_kbuild_user" = tb321fu-haptics ] || fail "local Kbuild user is not deterministic"
[ "$kernel_kbuild_host" = tb321fu-builder ] || fail "local Kbuild host is not deterministic"
[ "$kernel_kbuild_version" = 1 ] || fail "local Kbuild version is not deterministic"

kernel_bundle_id="$bundle_id"
kernel_kbuild_timestamp='2026-07-22 20:36:37 UTC'
kernel_kbuild_user=tb321fu-ci
kernel_kbuild_host=tb321fu-builder
kernel_kbuild_version=1
prepare_kernel_kbuild_identity
[ "$kernel_kbuild_user" = tb321fu-ci ] || fail "verified bundle Kbuild identity was replaced"
kernel_kbuild_user='bad bundle user'
require_failure 'invalid Kbuild user from verified kernel identity' \
  prepare_kernel_kbuild_identity

python3 - "$SCRIPT_DIR/build-tb321fu-haptics-deb.sh" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text()
assert 'cp --reflink=auto -- "$src" "$tmp"' in (Path(sys.argv[1]).parent / "common.sh").read_text()
prepare = source.index("prepare_inputs()")
metadata = source.index("load_kernel_bundle_metadata", prepare)
archive_download = source.index(
    'ci_download "$KERNEL_BUILD_ARCHIVE" "$archive" "$KERNEL_BUILD_ARCHIVE_SHA256"',
    prepare,
)
binding = source.index("haptics_validate_kernel_sdk_binding", archive_download)
manifest_download = source.index('ci_download "$KERNEL_SDK_MANIFEST" "$kernel_sdk_manifest_path"', binding)
preflight = source.index('verify-kernel-sdk.py" --archive-only', manifest_download)
extract = source.index('ci_extract_archive "$archive" "$extract"', preflight)
verifier = source.index('verify-kernel-sdk.py', extract)
remove_archive = source.index('rm -f -- "$archive"', verifier)
assert metadata < archive_download < binding < manifest_download < preflight < extract < verifier < remove_archive
assert '--kernel-release "$kernel_bundle_release"' in source[preflight:extract]
assert '--kernel-release "$kernel_bundle_release"' in source[verifier:remove_archive]
for field, variable in (
    ("kbuild-build-timestamp", "kernel_kbuild_timestamp"),
    ("kbuild-build-user", "kernel_kbuild_user"),
    ("kbuild-build-host", "kernel_kbuild_host"),
    ("kbuild-build-version", "kernel_kbuild_version"),
):
    assert f'{variable}=$(kernel_bundle_value {field})' in source
kernel_make = source[source.index("kernel_make()") : source.index("record_kernel_host_tools()")]
caller_args = kernel_make.index('"$@"')
for assignment in (
    'KERNELRELEASE="$kernel_release"',
    'KBUILD_BUILD_TIMESTAMP="$kernel_kbuild_timestamp"',
    'KBUILD_BUILD_USER="$kernel_kbuild_user"',
    'KBUILD_BUILD_HOST="$kernel_kbuild_host"',
    'KBUILD_BUILD_VERSION="$kernel_kbuild_version"',
):
    assert kernel_make.index(assignment) > caller_args
start = source.index("write_haptics_source_lock()")
end = source.index("\n}\n", start) + 2
block = source[start:end]
expected = [
    "schema",
    "haptics-output-mode",
    "haptics-producer-commit",
    "haptics-producer-state",
    "environment-policy",
    "environment-policy-sha256",
    "build-toolset-sha256",
    "build-tools-manifest",
    "build-tools-manifest-sha256",
    "aw86937-driver-sha256",
    "aw86937-build-source-sha256",
    "haptic-ram-firmware-sha256",
    "haptic-click-firmware-sha256",
    "haptic-test-helper-sha256",
    "aw86937-module-sha256",
    "haptic-test-helper-binary-sha256",
    "kernel-bundle-id",
    "kernel-release",
    "kernel-source-commit",
    "kernel-config-sha256",
    "kernel-build-input",
    "kernel-build-archive-sha256",
    "source-date-epoch",
]
actual = []
for line in block.splitlines():
    if "printf '" not in line:
        continue
    field = line.split("printf '", 1)[1].split("\\t", 1)[0]
    actual.append(field)
assert actual == expected, (actual, expected)
assert "tb321fu.haptics-source-lock/v3" in source
assert "tb321fu.haptics-source-lock/v3-local" in source
assert "haptics_output_mode=release-candidate" in source
assert "haptics_output_mode=local" in source
assert "kernel_build_input=kernel-sdk-archive" in source
PY

for token in \
  'HAPTICS_RELEASE_MODE=1' \
  'release haptics source lock has an unsupported schema' \
  'release haptics source lock does not identify a kernel SDK archive' \
  'release haptics source lock does not bind the requested kernel SDK archive' \
  'KERNEL_SDK_MANIFEST="$KERNEL_SDK_MANIFEST"'; do
  grep -Fq -- "$token" "$SCRIPT_DIR/build-tb321fu-haptics-deb-from-kernel-sdk.sh" ||
    fail "SDK wrapper omits release lock contract token: $token"
done
python3 - "$SCRIPT_DIR/build-tb321fu-haptics-deb-from-kernel-sdk.sh" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text()
preflight = source.index('ci_verify_clean_git_commit "$REPO_ROOT" "$HAPTICS_PRODUCER_COMMIT"')
fetch = source.index('ci_fetch_exact_git_commit')
producer = source.index('build-tb321fu-haptics-deb.sh', fetch)
assert preflight < fetch < producer
assert 'readonly KERNEL_SOURCE_FETCH_ATTEMPTS=4' in source
expected_call = '''ci_fetch_exact_git_commit \\
  "$KERNEL_SOURCE_REPO" \\
  "$KERNEL_SOURCE_COMMIT" \\
  "$kernel_source" \\
  "$KERNEL_SOURCE_FETCH_ATTEMPTS" \\
  "${HAPTICS_BUILD_TOOL_COMMAND_PATHS[timeout]}" \\
  "${HAPTICS_BUILD_TOOL_COMMAND_PATHS[sleep]}"'''
assert source.count(expected_call) == 1
PY
workflow=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)/.github/workflows/build.yml
readme=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)/README.md
grep -Fq 'HAPTICS_RELEASE_MODE=1' "$workflow" ||
  fail 'workflow does not inject release mode into the SDK wrapper'
grep -Fq 'all six locked inputs' "$readme" ||
  fail 'README does not describe the complete release input set'
grep -Fq 'kernel_sdk_manifest' "$readme" ||
  fail 'README does not document the kernel SDK manifest input'
grep -Fq 'at most four HTTP/1.1' "$readme" ||
  fail 'README does not document bounded fresh-repository kernel fetches'
grep -Fq 'minutes plus a 30-second forced-termination window' "$readme" ||
  fail 'README does not document the per-fetch wall-clock limit'
grep -Fq 'Redirects, automatic tag following' "$readme" ||
  fail 'README does not document the closed Git metadata fetch'
python3 - "$workflow" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text()
lines = source.splitlines()
for name in ("kernel_bundle_metadata", "kernel_bundle_metadata_sha256", "kernel_sdk_manifest"):
    start = lines.index(f"      {name}:")
    block = [lines[start]]
    for line in lines[start + 1 :]:
        if line.startswith("      ") and not line.startswith("        "):
            break
        block.append(line)
    assert "        required: true" in block, name

declaration = source.index("      kernel_sdk_manifest:")
input_env = source.index("          INPUT_KERNEL_SDK_MANIFEST: ${{ inputs.kernel_sdk_manifest }}")
validation = source.index('[[ "$INPUT_KERNEL_SDK_MANIFEST" =~ ^https://[^[:space:]]{1,2048}$ ]]')
export = source.index("printf 'KERNEL_SDK_MANIFEST=%s\\n' \"$INPUT_KERNEL_SDK_MANIFEST\"")
build_env = source.index('KERNEL_SDK_MANIFEST="$KERNEL_SDK_MANIFEST"')
wrapper = source.index('bash scripts/ci/build-tb321fu-haptics-deb-from-kernel-sdk.sh', build_env)
assert declaration < input_env < validation < export < build_env < wrapper
PY

printf 'HAPTICS_KERNEL_SDK_CONTRACT=PASS\n'
