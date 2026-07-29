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
assert metadata < archive_download < binding < manifest_download < preflight < extract < verifier
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
