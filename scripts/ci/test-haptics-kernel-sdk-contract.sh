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
fetch = source.index('ci_git -C "$kernel_source" fetch')
producer = source.index('build-tb321fu-haptics-deb.sh', fetch)
assert preflight < fetch < producer
PY
workflow=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)/.github/workflows/build.yml
readme=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)/README.md
grep -Fq 'HAPTICS_RELEASE_MODE=1' "$workflow" ||
  fail 'workflow does not inject release mode into the SDK wrapper'
grep -Fq 'all six locked inputs' "$readme" ||
  fail 'README does not describe the complete release input set'
grep -Fq 'kernel_sdk_manifest' "$readme" ||
  fail 'README does not document the kernel SDK manifest input'
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
